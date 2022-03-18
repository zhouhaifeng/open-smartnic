/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2017 ScyllaDB
 */
#include <seastar/core/app-template.hh>
#include <seastar/core/distributed.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/future.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/file.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/align.hh>
#include <seastar/core/timer.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/print.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/with_scheduling_group.hh>
#include <seastar/core/metrics_api.hh>
#include <seastar/core/io_intent.hh>
#include <chrono>
#include <vector>
#include <boost/range/irange.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/accumulators/accumulators.hpp>
#include <boost/accumulators/statistics/stats.hpp>
#include <boost/accumulators/statistics/max.hpp>
#include <boost/accumulators/statistics/mean.hpp>
#include <boost/accumulators/statistics/p_square_quantile.hpp>
#include <boost/accumulators/statistics/extended_p_square.hpp>
#include <boost/accumulators/statistics/extended_p_square_quantile.hpp>
#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/map.hpp>
#include <boost/array.hpp>
#include <iomanip>
#include <random>
#include <yaml-cpp/yaml.h>

using namespace seastar;
using namespace std::chrono_literals;
using namespace boost::accumulators;

static auto random_seed = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
static std::default_random_engine random_generator(random_seed);

class context;
enum class request_type { seqread, seqwrite, randread, randwrite, append, cpu };

namespace std {

template <>
struct hash<request_type> {
    size_t operator() (const request_type& type) const {
        return static_cast<size_t>(type);
    }
};

}

struct byte_size {
    uint64_t size;
};

struct duration_time {
    std::chrono::duration<float> time;
};

class shard_config {
    std::unordered_set<unsigned> _shards;
public:
    shard_config()
        : _shards(boost::copy_range<std::unordered_set<unsigned>>(boost::irange(0u, smp::count))) {}
    shard_config(std::unordered_set<unsigned> s) : _shards(std::move(s)) {}

    bool is_set(unsigned cpu) const {
        return _shards.count(cpu);
    }
};

struct shard_info {
    unsigned parallelism = 0;
    unsigned rps = 0;
    unsigned shares = 10;
    uint64_t request_size = 4 << 10;
    std::chrono::duration<float> think_time = 0ms;
    std::chrono::duration<float> think_after = 0ms;
    std::chrono::duration<float> execution_time = 1ms;
    seastar::scheduling_group scheduling_group = seastar::default_scheduling_group();
};

struct options {
    bool dsync = false;
};

class class_data;

struct job_config {
    std::string name;
    request_type type;
    shard_config shard_placement;
    ::shard_info shard_info;
    ::options options;
    // size of each individual file. Every class and every shard have its file, so in a normal
    // system with many shards we'll naturally have many files and that will push the data out
    // of the disk's cache
    uint64_t file_size;
    uint64_t offset_in_bdev;
    std::unique_ptr<class_data> gen_class_data();
};

std::array<double, 4> quantiles = { 0.5, 0.95, 0.99, 0.999};
static bool keep_files = false;

class class_data {
protected:
    using accumulator_type = accumulator_set<double, stats<tag::extended_p_square_quantile(quadratic), tag::mean, tag::max>>;

    job_config _config;
    uint64_t _alignment;
    uint64_t _last_pos = 0;
    uint64_t _offset = 0;

    io_priority_class _iop;
    seastar::scheduling_group _sg;

    size_t _data = 0;
    std::chrono::duration<float> _total_duration;

    std::chrono::steady_clock::time_point _start = {};
    accumulator_type _latencies;
    uint64_t _requests = 0;
    std::uniform_int_distribution<uint32_t> _pos_distribution;
    file _file;
    bool _think = false;
    timer<> _thinker;

    virtual future<> do_start(sstring dir, directory_entry_type type) = 0;
    virtual future<size_t> issue_request(char *buf, io_intent* intent) = 0;
public:
    class_data(job_config cfg)
        : _config(std::move(cfg))
        , _alignment(_config.shard_info.request_size >= 4096 ? 4096 : 512)
        , _iop(io_priority_class::register_one(name(), _config.shard_info.shares))
        , _sg(cfg.shard_info.scheduling_group)
        , _latencies(extended_p_square_probabilities = quantiles)
        , _pos_distribution(0,  _config.file_size / _config.shard_info.request_size)
        , _thinker([this] { think_tick(); })
    {
        if (_config.shard_info.think_after > 0us) {
            _thinker.arm(std::chrono::duration_cast<std::chrono::microseconds>(_config.shard_info.think_after));
        } else if (_config.shard_info.think_time > 0us) {
            _think = true;
        }
    }

    virtual ~class_data() = default;

private:

    void think_tick() {
        if (_think) {
            _think = false;
            _thinker.arm(std::chrono::duration_cast<std::chrono::microseconds>(_config.shard_info.think_after));
        } else {
            _think = true;
            _thinker.arm(std::chrono::duration_cast<std::chrono::microseconds>(_config.shard_info.think_time));
        }
    }

    future<> issue_requests_in_parallel(std::chrono::steady_clock::time_point stop, unsigned parallelism) {
        return parallel_for_each(boost::irange(0u, parallelism), [this, stop] (auto dummy) mutable {
            auto bufptr = allocate_aligned_buffer<char>(this->req_size(), _alignment);
            auto buf = bufptr.get();
            return do_until([stop] { return std::chrono::steady_clock::now() > stop; }, [this, buf, stop] () mutable {
                auto start = std::chrono::steady_clock::now();
                return issue_request(buf, nullptr).then([this, start, stop] (auto size) {
                    auto now = std::chrono::steady_clock::now();
                    if (now < stop) {
                        this->add_result(size, std::chrono::duration_cast<std::chrono::microseconds>(now - start));
                    }
                    return think();
                });
            }).finally([bufptr = std::move(bufptr)] {});
        });
    }

    future<> issue_requests_at_rate(std::chrono::steady_clock::time_point stop, unsigned rps) {
        return do_with(io_intent{}, 0u, [this, stop, rps] (io_intent& intent, unsigned& in_flight) {
            auto bufptr = allocate_aligned_buffer<char>(this->req_size(), _alignment);
            auto buf = bufptr.get();
            auto pause = std::chrono::duration_cast<std::chrono::microseconds>(1s) / rps;
            return do_until([stop] { return std::chrono::steady_clock::now() > stop; }, [this, buf, stop, pause, &intent, &in_flight] () mutable {
                auto start = std::chrono::steady_clock::now();
                in_flight++;
                (void)issue_request(buf, &intent).then([this, start, stop, &in_flight] (auto size) {
                    auto now = std::chrono::steady_clock::now();
                    if (now < stop) {
                        this->add_result(size, std::chrono::duration_cast<std::chrono::microseconds>(now - start));
                    }
                    in_flight--;
                    return make_ready_future<>();
                });
                return seastar::sleep(std::max(std::chrono::duration_cast<std::chrono::microseconds>((start + pause) - std::chrono::steady_clock::now()), 0us));
            }).then([&intent, &in_flight] {
                intent.cancel();
                return do_until([&in_flight] { return in_flight == 0; }, [] { return seastar::sleep(100ms /* ¯\_(ツ)_/¯ */); });
            }).finally([bufptr = std::move(bufptr)] {});
        });
    }

public:
    future<> issue_requests(std::chrono::steady_clock::time_point stop) {
        _start = std::chrono::steady_clock::now();
        return with_scheduling_group(_sg, [this, stop] {
            if (parallelism() != 0) {
                return issue_requests_in_parallel(stop, parallelism());
            } else /* rps() != 0 */ {
                assert(rps() != 0);
                return issue_requests_at_rate(stop, rps());
            }
        }).then([this] {
            _total_duration = std::chrono::steady_clock::now() - _start;
        });
    }

    future<> think() {
        if (_think) {
            return seastar::sleep(std::chrono::duration_cast<std::chrono::microseconds>(_config.shard_info.think_time));
        } else {
            return make_ready_future<>();
        }
    }
    // Generate the test file for reads and writes alike. It is much simpler to just generate one file per job instead of expecting
    // job dependencies between creators and consumers. So every job (a class in a shard) will have its own file and will operate
    // this file differently depending on the type:
    //
    // sequential reads  : will read the file from pos = 0 onwards, back to 0 on EOF
    // sequential writes : will write the file from pos = 0 onwards, back to 0 on EOF
    // random reads      : will read the file at random positions, between 0 and EOF
    // random writes     : will overwrite the file at a random position, between 0 and EOF
    // append            : will write to the file from pos = EOF onwards, always appending to the end.
    // cpu               : CPU-only load, file is not created.
    future<> start(sstring dir, directory_entry_type type) {
        return do_start(dir, type);
    }

    future<> stop() {
        if (_file) {
            return _file.close();
        }
        return make_ready_future<>();
    }

    const sstring name() const {
        return _config.name;
    }

protected:
    sstring type_str() const {
        return std::unordered_map<request_type, sstring>{
            { request_type::seqread, "SEQ READ" },
            { request_type::seqwrite, "SEQ WRITE" },
            { request_type::randread, "RAND READ" },
            { request_type::randwrite, "RAND WRITE" },
            { request_type::append , "APPEND" },
            { request_type::cpu , "CPU" },
        }[_config.type];;
    }

    request_type req_type() const {
        return _config.type;
    }

    sstring think_time() const {
        if (_config.shard_info.think_time == std::chrono::duration<float>(0)) {
            return "NO think time";
        } else {
            return format("{:d} us think time", std::chrono::duration_cast<std::chrono::microseconds>(_config.shard_info.think_time).count());
        }
    }

    size_t req_size() const {
        return _config.shard_info.request_size;
    }

    unsigned parallelism() const {
        return _config.shard_info.parallelism;
    }

    unsigned rps() const {
        return _config.shard_info.rps;
    }

    unsigned shares() const {
        return _config.shard_info.shares;
    }

    std::chrono::duration<float> total_duration() const {
        return _total_duration;
    }

    uint64_t file_size_mb() const {
        return _config.file_size >> 20;
    }

    uint64_t total_data() const {
        return _data;
    }

    uint64_t max_latency() const {
        return max(_latencies);
    }

    uint64_t average_latency() const {
        return mean(_latencies);
    }

    uint64_t quantile_latency(double q) const {
        return quantile(_latencies, quantile_probability = q);
    }

    uint64_t requests() const noexcept {
        return _requests;
    }

    bool is_sequential() const {
        return (req_type() == request_type::seqread) || (req_type() == request_type::seqwrite);
    }
    bool is_random() const {
        return (req_type() == request_type::randread) || (req_type() == request_type::randwrite);
    }

    uint64_t get_pos() {
        uint64_t pos;
        if (is_random()) {
            pos = _pos_distribution(random_generator) * req_size();
        } else {
            pos = _last_pos + req_size();
            if (is_sequential() && (pos >= _config.file_size)) {
                pos = 0;
            }
        }
        _last_pos = pos;
        return pos + _offset;
    }

    void add_result(size_t data, std::chrono::microseconds latency) {
        _data += data;
        _latencies(latency.count());
        _requests++;
    }

public:
    virtual void emit_results(YAML::Emitter& out) = 0;
};

class io_class_data : public class_data {
public:
    io_class_data(job_config cfg) : class_data(std::move(cfg)) {}

    future<> do_start(sstring path, directory_entry_type type) override {
        if (type == directory_entry_type::directory) {
            return do_start_on_directory(path);
        }

        if (type == directory_entry_type::block_device) {
            return do_start_on_bdev(path);
        }

        throw std::runtime_error(format("Unsupported storage. {} should be directory or block device", path));
    }

private:
    future<> do_start_on_directory(sstring dir) {
        auto fname = format("{}/test-{}-{:d}", dir, name(), this_shard_id());
        auto flags = open_flags::rw | open_flags::create;
        if (_config.options.dsync) {
            flags |= open_flags::dsync;
        }
        file_open_options options;
        options.extent_allocation_size_hint = _config.file_size;
        options.append_is_unlikely = true;
        return open_file_dma(fname, flags, options).then([this, fname] (auto f) {
            _file = f;
            auto maybe_remove_file = [] (sstring fname) {
                return keep_files ? make_ready_future<>() : remove_file(fname);
            };
            return maybe_remove_file(fname).then([this] {
                return _file.size().then([this] (uint64_t size) {
                    return _file.truncate(_config.file_size).then([this, size] {
                        if (size >= _config.file_size) {
                            return make_ready_future<>();
                        }

                        auto bufsize = 256ul << 10;
                        return do_with(boost::irange(0ul, (_config.file_size / bufsize) + 1), [this, bufsize] (auto& pos) mutable {
                            return max_concurrent_for_each(pos.begin(), pos.end(), 64, [this, bufsize] (auto pos) mutable {
                                auto bufptr = allocate_aligned_buffer<char>(bufsize, 4096);
                                auto buf = bufptr.get();
                                std::uniform_int_distribution<char> fill('@', '~');
                                memset(buf, fill(random_generator), bufsize);
                                pos = pos * bufsize;
                                return _file.dma_write(pos, buf, bufsize).finally([this, bufptr = std::move(bufptr), pos] {
                                    if ((this->req_type() == request_type::append) && (pos > _last_pos)) {
                                        _last_pos = pos;
                                    }
                                }).discard_result();
                            });
                        }).then([this] {
                            return _file.flush();
                        });
                    });
                });
            });
        });
    }

    future<> do_start_on_bdev(sstring name) {
        auto flags = open_flags::rw;
        if (_config.options.dsync) {
            flags |= open_flags::dsync;
        }

        return open_file_dma(name, flags).then([this] (auto f) {
            _file = std::move(f);
            return _file.size().then([this] (uint64_t size) {
                auto shard_area_size = align_down<uint64_t>(size / smp::count, 1 << 20);
                if (_config.offset_in_bdev + _config.file_size > shard_area_size) {
                    throw std::runtime_error("Data doesn't fit the blockdevice");
                }
                _offset = shard_area_size * this_shard_id() + _config.offset_in_bdev;
                return make_ready_future<>();
            });
        });
    }

    void emit_one_metrics(YAML::Emitter& out, sstring m_name) {
        const auto& values = seastar::metrics::impl::get_value_map();
        const auto& mf = values.find(m_name);
        assert(mf != values.end());
        for (auto&& mi : mf->second) {
            auto&& cname = mi.first.find("class");
            if (cname != mi.first.end() && cname->second == name()) {
                out << YAML::Key << m_name << YAML::Value << mi.second->get_function()().d();
            }
        }
    }

    void emit_metrics(YAML::Emitter& out) {
        emit_one_metrics(out, "io_queue_total_exec_sec");
        emit_one_metrics(out, "io_queue_total_delay_sec");
        emit_one_metrics(out, "io_queue_total_operations");
        emit_one_metrics(out, "io_queue_starvation_time_sec");
    }

public:
    virtual void emit_results(YAML::Emitter& out) override {
        auto throughput_kbs = (total_data() >> 10) / total_duration().count();
        auto iops = requests() / total_duration().count();
        out << YAML::Key << "throughput" << YAML::Value << throughput_kbs << YAML::Comment("kB/s");
        out << YAML::Key << "IOPS" << YAML::Value << iops;
        out << YAML::Key << "latencies" << YAML::Comment("usec");
        out << YAML::BeginMap;
        out << YAML::Key << "average" << YAML::Value << average_latency();
        for (auto& q: quantiles) {
            out << YAML::Key << fmt::format("p{}", q) << YAML::Value << quantile_latency(q);
        }
        out << YAML::Key << "max" << YAML::Value << max_latency();
        out << YAML::EndMap;
        out << YAML::Key << "stats" << YAML::BeginMap;
        out << YAML::Key << "total_requests" << YAML::Value << requests();
        emit_metrics(out);
        out << YAML::EndMap;
    }
};

class read_io_class_data : public io_class_data {
public:
    read_io_class_data(job_config cfg) : io_class_data(std::move(cfg)) {}

    future<size_t> issue_request(char *buf, io_intent* intent) override {
        return _file.dma_read(this->get_pos(), buf, this->req_size(), _iop, intent);
    }
};

class write_io_class_data : public io_class_data {
public:
    write_io_class_data(job_config cfg) : io_class_data(std::move(cfg)) {}

    future<size_t> issue_request(char *buf, io_intent* intent) override {
        return _file.dma_write(this->get_pos(), buf, this->req_size(), _iop, intent);
    }
};

class cpu_class_data : public class_data {
public:
    cpu_class_data(job_config cfg) : class_data(std::move(cfg)) {}

    future<> do_start(sstring dir, directory_entry_type type) override {
        return make_ready_future<>();
    }

    future<size_t> issue_request(char *buf, io_intent* intent) override {
        // We do want the execution time to be a busy loop, and not just a bunch of
        // continuations until our time is up: by doing this we can also simulate the behavior
        // of I/O continuations in the face of reactor stalls.
        auto start  = std::chrono::steady_clock::now();
        do {
        } while ((std::chrono::steady_clock::now() - start) < _config.shard_info.execution_time);
        return make_ready_future<size_t>(1);
    }

    virtual void emit_results(YAML::Emitter& out) override {
        auto throughput = total_data() / total_duration().count();
        out << YAML::Key << "throughput" << YAML::Value << throughput;
    }
};

std::unique_ptr<class_data> job_config::gen_class_data() {
    if (type == request_type::cpu) {
        return std::make_unique<cpu_class_data>(*this);
    } else if ((type == request_type::seqread) || (type == request_type::randread)) {
        return std::make_unique<read_io_class_data>(*this);
    } else {
        return std::make_unique<write_io_class_data>(*this);
    }
}

/// YAML parsing functions
namespace YAML {
template<>
struct convert<byte_size> {
    static bool decode(const Node& node, byte_size& bs) {
        auto str = node.as<std::string>();
        unsigned shift = 0;
        if (str.back() == 'B') {
            str.pop_back();
            shift = std::unordered_map<char, unsigned>{
                { 'k', 10 },
                { 'M', 20 },
                { 'G', 30 },
            }[str.back()];
            str.pop_back();
        }
        bs.size = (boost::lexical_cast<size_t>(str) << shift);
        return bs.size >= 512;
    }
};

template<>
struct convert<duration_time> {
    static bool decode(const Node& node, duration_time& dt) {
        auto str = node.as<std::string>();
        if (str == "0") {
            dt.time = 0ns;
            return true;
        }
        if (str.back() != 's') {
            return false;
        }
        str.pop_back();
        std::unordered_map<char, std::chrono::duration<float>> unit = {
            { 'n', 1ns },
            { 'u', 1us },
            { 'm', 1ms },
        };

        if (unit.count(str.back())) {
            auto u = str.back();
            str.pop_back();
            dt.time = (boost::lexical_cast<size_t>(str) * unit[u]);
        } else {
            dt.time = (boost::lexical_cast<size_t>(str) * 1s);
        }
        return true;
    }
};

template<>
struct convert<shard_config> {
    static bool decode(const Node& node, shard_config& shards) {
        try {
            auto str = node.as<std::string>();
            return (str == "all");
        } catch (YAML::TypedBadConversion<std::string>& e) {
            shards = shard_config(boost::copy_range<std::unordered_set<unsigned>>(node.as<std::vector<unsigned>>()));
            return true;
        }
        return false;
    }
};

template<>
struct convert<request_type> {
    static bool decode(const Node& node, request_type& rt) {
        static std::unordered_map<std::string, request_type> mappings = {
            { "seqread", request_type::seqread },
            { "seqwrite", request_type::seqwrite},
            { "randread", request_type::randread },
            { "randwrite", request_type::randwrite },
            { "append", request_type::append},
            { "cpu", request_type::cpu},
        };
        auto reqstr = node.as<std::string>();
        if (!mappings.count(reqstr)) {
            return false;
        }
        rt = mappings[reqstr];
        return true;
    }
};

template<>
struct convert<shard_info> {
    static bool decode(const Node& node, shard_info& sl) {
        if (node["parallelism"]) {
            sl.parallelism = node["parallelism"].as<unsigned>();
        }
        if (node["rps"]) {
            sl.rps = node["rps"].as<unsigned>();
        }
        if ((sl.parallelism == 0) == (sl.rps == 0)) {
            fmt::print("Must specify exactly one of 'parallelism' or 'rps' parameters\n");
            return false;
        }

        if (node["shares"]) {
            sl.shares = node["shares"].as<unsigned>();
        }
        if (node["reqsize"]) {
            sl.request_size = node["reqsize"].as<byte_size>().size;
        }
        if (node["think_time"]) {
            sl.think_time = node["think_time"].as<duration_time>().time;
        }
        if (node["think_after"]) {
            sl.think_after = node["think_after"].as<duration_time>().time;
        }
        if (node["execution_time"]) {
            sl.execution_time = node["execution_time"].as<duration_time>().time;
        }
        return true;
    }
};

template<>
struct convert<options> {
    static bool decode(const Node& node, options& op) {
        if (node["dsync"]) {
            op.dsync = node["dsync"].as<bool>();
        }
        return true;
    }
};

template<>
struct convert<job_config> {
    static bool decode(const Node& node, job_config& cl) {
        cl.name = node["name"].as<std::string>();
        cl.type = node["type"].as<request_type>();
        cl.shard_placement = node["shards"].as<shard_config>();
        // The data_size is used to divide the available (and effectively
        // constant) disk space between workloads. Each shard inside the
        // workload thus uses its portion of the assigned space.
        if (node["data_size"]) {
            cl.file_size = node["data_size"].as<byte_size>().size / smp::count;
        } else {
            cl.file_size = 1ull << 30; // 1G by default
        }
        if (node["shard_info"]) {
            cl.shard_info = node["shard_info"].as<shard_info>();
        }
        if (node["options"]) {
            cl.options = node["options"].as<options>();
        }
        return true;
    }
};
}

/// Each shard has one context, and the context is responsible for creating the classes that should
/// run in this shard.
class context {
    std::vector<std::unique_ptr<class_data>> _cl;

    sstring _dir;
    directory_entry_type _type;
    std::chrono::seconds _duration;

    semaphore _finished;
public:
    context(sstring dir, directory_entry_type dtype, std::vector<job_config> req_config, unsigned duration)
            : _cl(boost::copy_range<std::vector<std::unique_ptr<class_data>>>(req_config
                | boost::adaptors::filtered([] (auto& cfg) { return cfg.shard_placement.is_set(this_shard_id()); })
                | boost::adaptors::transformed([] (auto& cfg) { return cfg.gen_class_data(); })
            ))
            , _dir(dir)
            , _type(dtype)
            , _duration(duration)
            , _finished(0)
    {}

    future<> stop() {
        return parallel_for_each(_cl, [] (std::unique_ptr<class_data>& cl) {
            return cl->stop();
        });
    }

    future<> start() {
        return parallel_for_each(_cl, [this] (std::unique_ptr<class_data>& cl) {
            return cl->start(_dir, _type);
        });
    }

    future<> issue_requests() {
        return parallel_for_each(_cl.begin(), _cl.end(), [this] (std::unique_ptr<class_data>& cl) {
            return cl->issue_requests(std::chrono::steady_clock::now() + _duration).finally([this] {
                _finished.signal(1);
            });
        });
    }

    future<> emit_results(YAML::Emitter& out) {
        return _finished.wait(_cl.size()).then([this, &out] {
            for (auto& cl: _cl) {
                out << YAML::Key << cl->name();
                out << YAML::BeginMap;
                cl->emit_results(out);
                out << YAML::EndMap;
            }
            return make_ready_future<>();
        });
    }
};

static void show_results(distributed<context>& ctx) {
    YAML::Emitter out;
    out << YAML::BeginDoc;
    out << YAML::BeginSeq;
    for (unsigned i = 0; i < smp::count; ++i) {
        out << YAML::BeginMap;
        out << YAML::Key << "shard" << YAML::Value << i;
        ctx.invoke_on(i, [&out] (auto& c) {
            return c.emit_results(out);
        }).get();
        out << YAML::EndMap;
    }
    out << YAML::EndSeq;
    out << YAML::EndDoc;
    std::cout << out.c_str();
}

int main(int ac, char** av) {
    namespace bpo = boost::program_options;

    app_template app;
    auto opt_add = app.add_options();
    opt_add
        ("storage", bpo::value<sstring>()->default_value("."), "directory or block device where to execute the test")
        ("duration", bpo::value<unsigned>()->default_value(10), "for how long (in seconds) to run the test")
        ("conf", bpo::value<sstring>()->default_value("./conf.yaml"), "YAML file containing benchmark specification")
        ("keep-files", bpo::value<bool>()->default_value(false), "keep test files, next run may re-use them")
    ;

    distributed<context> ctx;
    return app.run(ac, av, [&] {
        return seastar::async([&] {
            auto& opts = app.configuration();
            auto& storage = opts["storage"].as<sstring>();

            auto st_type = engine().file_type(storage).get0();

            if (!st_type) {
                throw std::runtime_error(format("Unknown storage {}", storage));
            }

            if (*st_type == directory_entry_type::directory) {
                auto fs = file_system_at(storage).get0();
                if (fs != fs_type::xfs) {
                    throw std::runtime_error(format("This is a performance test. {} is not on XFS", storage));
                }
            }

            keep_files = opts["keep-files"].as<bool>();
            auto& duration = opts["duration"].as<unsigned>();
            auto& yaml = opts["conf"].as<sstring>();
            YAML::Node doc = YAML::LoadFile(yaml);
            auto reqs = doc.as<std::vector<job_config>>();

            parallel_for_each(reqs, [] (auto& r) {
                return seastar::create_scheduling_group(r.name, r.shard_info.shares).then([&r] (seastar::scheduling_group sg) {
                    r.shard_info.scheduling_group = sg;
                });
            }).get();

            if (*st_type == directory_entry_type::block_device) {
                uint64_t off = 0;
                for (job_config& r : reqs) {
                    r.offset_in_bdev = off;
                    off += r.file_size;
                }
            }

            ctx.start(storage, *st_type, reqs, duration).get0();
            engine().at_exit([&ctx] {
                return ctx.stop();
            });
            std::cout << "Creating initial files..." << std::endl;
            ctx.invoke_on_all([] (auto& c) {
                return c.start();
            }).get();
            std::cout << "Starting evaluation..." << std::endl;
            ctx.invoke_on_all([] (auto& c) {
                return c.issue_requests();
            }).get();
            show_results(ctx);
            ctx.stop().get0();
        }).or_terminate();
    });
}
