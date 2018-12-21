/*
 * Copyright 2018-present Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#include "aws/lambda-runtime/runtime.h"
#include "aws/logging/logging.h"

#include <vector>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <signal.h>
#include <sys/ucontext.h>
#include <execinfo.h>
#include <cxxabi.h>

static char const LOG_TAG[] = "LAMBDA_RUNTIME";

namespace aws {
namespace lambda_runtime {

class signal_manager {
public:
    signal_manager();
    ~signal_manager();

private:
    static void on_signal(int signo, siginfo_t* info, void* ctx);
    static void handle_signal(int signo, siginfo_t* info, void* ctx);
    static std::string analyze(char* frame);
    static std::string demangle(char const* function_name);
    stack_t m_stack;
    void* m_stack_memory;
    static int constexpr m_signals[] = {
        SIGABRT, // Abort signal from abort(3)
        SIGBUS,  // Bus error (bad memory access)
        SIGFPE,  // Floating point exception
        SIGILL,  // Illegal Instruction
        SIGSEGV  // Invalid memory reference
    };
};

signal_manager::signal_manager()
{
    m_stack_memory = malloc(SIGSTKSZ);
    assert(m_stack_memory);
    m_stack.ss_sp = m_stack_memory;
    m_stack.ss_size = SIGSTKSZ;
    m_stack.ss_flags = 0;
    if (sigaltstack(&m_stack, nullptr)) {
        logging::log_error(LOG_TAG, "Failed to set signal handler stack. Error: %s", std::strerror(errno));
        return;
    }

    for (auto signo : m_signals) {
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_flags = (SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESETHAND);
        sigfillset(&action.sa_mask);
        sigdelset(&action.sa_mask, signo);
        action.sa_sigaction = &on_signal;

        if (sigaction(signo, &action, nullptr)) {
            logging::log_error(
                LOG_TAG, "Failed to set signal handler action for signal %d. Error: %s", signo, std::strerror(errno));
        }
    }
}

signal_manager::~signal_manager()
{
    free(m_stack_memory);
}

void signal_manager::on_signal(int signo, siginfo_t* info, void* ctx)
{
    handle_signal(signo, info, ctx);
    // restore the default signal
    signal(signo, SIG_DFL);
    // raise the signal again to be handled by the default handler (usually terminates the process)
    raise(signo);
}

void signal_manager::handle_signal(int signo, siginfo_t* info, void* ctx)
{
    (void)signo; // suppress unused warning
    (void)info;  // suppress unused warning
    ucontext_t* uctx = static_cast<ucontext_t*>(ctx);
#ifdef REG_RIP // x86_64
    void* error_addr = reinterpret_cast<void*>(uctx->uc_mcontext.gregs[REG_RIP]);
#elif defined(__APPLE__)
    void* error_addr = reinterpret_cast<void*>(uctx->uc_mcontext->__ss.__rip);
#endif

    std::vector<void*> stack_frames(32);
    auto count = backtrace(&stack_frames[0], static_cast<int>(stack_frames.size()));
    stack_frames.resize(count);
    size_t error_frame_index = 0;
    if (error_addr) {
        for (size_t i = 0; i < stack_frames.size(); i++) {
            if (error_addr == stack_frames[i]) {
                error_frame_index = i;
                break;
            }
        }
    }

    auto frames = backtrace_symbols(&stack_frames[error_frame_index], static_cast<int>(stack_frames.size()));
    if (!frames) {
        logging::log_error(LOG_TAG, "Failed to set read backtrace symbols.");
        return;
    }

    logging::log_error(LOG_TAG, "Stack trace (most recent call first):");
    for (size_t i = error_frame_index; i < stack_frames.size(); i++) {
        logging::log_error(LOG_TAG, analyze(frames[i]).c_str());
    }

    free(frames);
}

std::string signal_manager::analyze(char* frame)
{
    char* filename = frame;
    char* funcname = filename;
    while (*funcname && *funcname != '(') {
        funcname++;
    }

    std::string source(filename, funcname);

    if (*funcname) { // if it's not end of string (e.g. from last frame ip==0)
        funcname += 1;
        char* funcname_end = funcname;
        while (*funcname_end && *funcname_end != ')' && *funcname_end != '+') {
            funcname_end++;
        }
        *funcname_end = '\0';
        source += " in ";
        source += demangle(funcname);
    }
    return source;
}

std::string signal_manager::demangle(char const* function_name)
{
    auto friendly_name =
        abi::__cxa_demangle(function_name, nullptr /*output_buffer*/, nullptr /*length*/, nullptr /*status*/);
    if (friendly_name) {
        std::string result(friendly_name);
        free(friendly_name);
        return result;
    }
    return function_name;
}

void install_signal_handlers()
{
    static aws::signal_manager manager;
}

} // namespace lambda_runtime
} // namespace aws
