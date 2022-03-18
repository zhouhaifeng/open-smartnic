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
 * author: Niek J Bouman
 * reviewer: Avi Kivity
 * November 2021
 */ 

#pragma once

#include <iterator>
#include <cstddef>
#include <type_traits>
#include <vector>
#include <seastar/core/future.hh>
#include <seastar/core/shared_ptr.hh>

namespace seastar {

template <class Sequence>
struct when_any_result {
    std::size_t index;
    Sequence futures;
};

namespace internal {
class waiter {
    bool _done = false;
    promise<std::size_t> _promise;

public:
    void done(std::size_t index) {
        if (!_done) {
            _done = true;
            _promise.set_value(index);
        }
    }
    auto get_future() { return _promise.get_future(); }
};

} // namespace internal

/// Wait for the first of multiple futures to complete (iterator version).
///
/// Given a range of futures as input, wait for the first of them
/// to resolve (either successfully or with an exception), and return
/// all of them in a \c when_any_result (following the concurrency TS from 
/// the standard library), containing a std::vector to all futures
/// and the index (into the vector) of the future that resolved.
///
/// \param begin an \c InputIterator designating the beginning of the range of futures
/// \param end an \c InputIterator designating the end of the range of futures
/// \return a \c when_any_result of all the futures in the input; when
///         ready, at least one of the contained futures (the one indicated by index) will be ready.
template <class FutureIterator>
SEASTAR_CONCEPT( requires requires (FutureIterator i) { { *i++ }; requires is_future<std::remove_reference_t<decltype(*i)>>::value; } )
auto when_any(FutureIterator begin, FutureIterator end) noexcept
  -> future<when_any_result<std::vector<std::decay_t<typename std::iterator_traits<FutureIterator>::value_type>>>>
{
    using ReturnType = when_any_result<std::vector<typename std::iterator_traits<FutureIterator>::value_type>>;
    if (begin == end) {
        return make_ready_future<ReturnType>();
    }
    ReturnType result;
    result.futures.reserve(std::distance(begin, end));
    auto waiter_obj = make_lw_shared<internal::waiter>();
    std::size_t index{0};
    for (auto it = begin; it != end; ++it) {
        if (it->available()) {
            result.futures.push_back(std::move(*it));
            waiter_obj->done(index);
        } else {
            result.futures.push_back(it->finally([waiter_obj, index] {
                waiter_obj->done(index);
            }));
        }
        index++;
    }
    return waiter_obj->get_future().then(
        [result = std::move(result)](std::size_t index) mutable {
            result.index = index;
            return std::move(result);
        }
    );
}
} // namespace seastar
