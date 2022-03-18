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
 * Copyright (C) 2018 ScyllaDB Ltd.
 */

#pragma once

#include <seastar/core/future.hh>
#include <seastar/core/thread.hh>

#include <seastar/testing/seastar_test.hh>

#define SEASTAR_THREAD_TEST_CASE_EXPECTED_FAILURES(name, failures) \
    struct name : public seastar::testing::seastar_test { \
        const char* get_test_file() override { return __FILE__; } \
        const char* get_name() override { return #name; } \
        int get_expected_failures() override { return failures; } \
        seastar::future<> run_test_case() override { \
            return seastar::async([this] { \
                do_run_test_case(); \
            }); \
        } \
        void do_run_test_case(); \
    }; \
    static name name ## _instance; \
    void name::do_run_test_case()

#define SEASTAR_THREAD_TEST_CASE(name) \
    SEASTAR_THREAD_TEST_CASE_EXPECTED_FAILURES(name, 0)
