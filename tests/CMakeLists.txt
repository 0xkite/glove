add_executable(smoke_test smoke_test.cpp)
target_link_libraries(smoke_test PRIVATE glove_kernel)
add_test(NAME smoke COMMAND smoke_test)

add_executable(host_config_test host/config_test.cpp)
target_link_libraries(host_config_test PRIVATE glove_host glove_supervisor)
add_test(NAME host_config COMMAND host_config_test)

add_executable(host_daemon_test host/daemon_test.cpp)
target_link_libraries(host_daemon_test PRIVATE glove_host)
add_test(NAME host_daemon COMMAND host_daemon_test)

add_executable(thread_smoke_test thread_smoke_test.cpp)
target_link_libraries(thread_smoke_test PRIVATE glove_kernel)
add_test(NAME thread_smoke COMMAND thread_smoke_test)

add_executable(mcp_transport_round_trip_test mcp/transport_round_trip_test.cpp)
target_link_libraries(mcp_transport_round_trip_test PRIVATE glove_kernel)
add_test(NAME mcp_transport_round_trip COMMAND mcp_transport_round_trip_test)

add_executable(mcp_codec_test mcp/codec_test.cpp)
target_link_libraries(mcp_codec_test PRIVATE glove_kernel glaze::glaze)
target_include_directories(mcp_codec_test PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>)
add_test(NAME mcp_codec COMMAND mcp_codec_test)

add_executable(mcp_jsonrpc_client_test mcp/jsonrpc_client_test.cpp)
target_link_libraries(mcp_jsonrpc_client_test PRIVATE glove_kernel glaze::glaze)
target_include_directories(mcp_jsonrpc_client_test PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>)
add_test(NAME mcp_jsonrpc_client COMMAND mcp_jsonrpc_client_test)

add_executable(mcp_initialize_test mcp/initialize_test.cpp)
target_link_libraries(mcp_initialize_test PRIVATE glove_kernel)
add_test(NAME mcp_initialize COMMAND mcp_initialize_test)

add_executable(mcp_lazy_init_test mcp/lazy_init_test.cpp)
target_link_libraries(mcp_lazy_init_test PRIVATE glove_kernel glaze::glaze)
target_include_directories(mcp_lazy_init_test PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>)
add_test(NAME mcp_lazy_init COMMAND mcp_lazy_init_test)

add_executable(mcp_protocol_version_test mcp/protocol_version_test.cpp)
target_link_libraries(mcp_protocol_version_test PRIVATE glove_kernel glaze::glaze)
target_include_directories(mcp_protocol_version_test PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>)
add_test(NAME mcp_protocol_version COMMAND mcp_protocol_version_test)

add_executable(policy_engine_test policy/engine_test.cpp)
target_link_libraries(policy_engine_test PRIVATE glove_kernel)
add_test(NAME policy_engine COMMAND policy_engine_test)

add_executable(policy_client_test policy/policy_client_test.cpp)
target_link_libraries(policy_client_test PRIVATE glove_kernel)
add_test(NAME policy_client COMMAND policy_client_test)

add_executable(policy_jsonpath_engine_test policy/jsonpath_engine_test.cpp)
target_link_libraries(policy_jsonpath_engine_test PRIVATE glove_kernel)
add_test(NAME policy_jsonpath_engine COMMAND policy_jsonpath_engine_test)

add_executable(net_egress_proxy_test net/egress_proxy_test.cpp)
target_link_libraries(net_egress_proxy_test PRIVATE glove_kernel)
add_test(NAME net_egress_proxy COMMAND net_egress_proxy_test)
set_tests_properties(net_egress_proxy PROPERTIES TIMEOUT 30)

add_executable(audit_client_test audit/audit_client_test.cpp)
target_link_libraries(audit_client_test PRIVATE glove_kernel)
add_test(NAME audit_client COMMAND audit_client_test)

add_executable(audit_jsonl_sink_test audit/jsonl_sink_test.cpp)
target_link_libraries(audit_jsonl_sink_test PRIVATE glove_kernel)
add_test(NAME audit_jsonl_sink COMMAND audit_jsonl_sink_test)

add_executable(container_profile_test container/profile_test.cpp)
target_link_libraries(container_profile_test PRIVATE glove_kernel)
add_test(NAME container_profile COMMAND container_profile_test)

add_executable(container_resource_monitor_test container/resource_monitor_test.cpp)
target_link_libraries(container_resource_monitor_test PRIVATE glove_container)
target_include_directories(container_resource_monitor_test PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container>
)
add_test(NAME container_resource_monitor COMMAND container_resource_monitor_test)
set_tests_properties(container_resource_monitor PROPERTIES TIMEOUT 10)

add_executable(container_output_pump_test container/output_pump_test.cpp)
target_link_libraries(container_output_pump_test PRIVATE glove_container)
target_include_directories(container_output_pump_test PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container>
)
add_test(NAME container_output_pump COMMAND container_output_pump_test)
set_tests_properties(container_output_pump PROPERTIES TIMEOUT 10)

add_executable(container_sha256_test container/sha256_test.cpp)
target_link_libraries(container_sha256_test PRIVATE glove_container)
target_include_directories(container_sha256_test PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container>
)
add_test(NAME container_sha256 COMMAND container_sha256_test)

add_executable(container_receipt_chain_test container/receipt_chain_test.cpp)
target_link_libraries(container_receipt_chain_test PRIVATE glove_container)
add_test(NAME container_receipt_chain COMMAND container_receipt_chain_test)

add_executable(container_receipt_journal_test container/receipt_journal_test.cpp)
target_link_libraries(container_receipt_journal_test PRIVATE glove_container)
add_test(NAME container_receipt_journal COMMAND container_receipt_journal_test)

add_executable(container_receipt_producer_test container/receipt_producer_test.cpp)
target_link_libraries(container_receipt_producer_test PRIVATE glove_container)
add_test(NAME container_receipt_producer COMMAND container_receipt_producer_test)

add_executable(control_receipt_audit_protocol_test control/receipt_audit_protocol_test.cpp)
target_link_libraries(control_receipt_audit_protocol_test PRIVATE glove_control glaze::glaze)
target_include_directories(control_receipt_audit_protocol_test PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
)
add_test(NAME control_receipt_audit_protocol COMMAND control_receipt_audit_protocol_test)

add_executable(control_session_registry_test control/session_registry_test.cpp)
target_link_libraries(control_session_registry_test PRIVATE glove_control)
target_include_directories(control_session_registry_test PRIVATE
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
)
add_test(NAME control_session_registry COMMAND control_session_registry_test)

if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(
        control_receipt_audit_server_fixture
        control/receipt_audit_server_fixture.cpp
    )
    target_link_libraries(control_receipt_audit_server_fixture PRIVATE glove_control)

    add_executable(gloved_lifecycle_test control/gloved_lifecycle_test.cpp)
    target_link_libraries(gloved_lifecycle_test PRIVATE glove_control glove_host glaze::glaze)
    target_include_directories(gloved_lifecycle_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
    )
    target_compile_definitions(gloved_lifecycle_test PRIVATE
        GLOVED_BIN="$<TARGET_FILE:gloved>"
    )
    add_dependencies(gloved_lifecycle_test gloved)
    add_test(NAME gloved_lifecycle COMMAND gloved_lifecycle_test)
    set_tests_properties(gloved_lifecycle PROPERTIES TIMEOUT 15)

    if(GLOVE_ENABLE_SAGE_INTEROP_TEST)
        find_program(GLOVE_CARGO_EXECUTABLE NAMES cargo REQUIRED)
        set(GLOVE_SAGE_MANIFEST "${CMAKE_SOURCE_DIR}/../sage/Cargo.toml")
        if(NOT EXISTS "${GLOVE_SAGE_MANIFEST}")
            message(FATAL_ERROR
                "GLOVE_ENABLE_SAGE_INTEROP_TEST requires ../sage/Cargo.toml"
            )
        endif()
        add_test(
            NAME sage_receipt_audit_interop
            COMMAND
                "${CMAKE_COMMAND}" -E env
                "GLOVE_RECEIPT_SERVER_FIXTURE=$<TARGET_FILE:control_receipt_audit_server_fixture>"
                "${GLOVE_CARGO_EXECUTABLE}" test
                --manifest-path "${GLOVE_SAGE_MANIFEST}"
                -p sage-daemon --lib
                sage_client_interoperates_with_the_glove_receipt_server
                -- --ignored
        )
        set_tests_properties(sage_receipt_audit_interop PROPERTIES TIMEOUT 600)
    endif()
endif()

add_executable(supervisor_path_alias_test supervisor/path_alias_test.cpp)
target_link_libraries(supervisor_path_alias_test PRIVATE glove_kernel)
add_test(NAME supervisor_path_alias COMMAND supervisor_path_alias_test)

add_executable(supervisor_path_exposure_test supervisor/path_exposure_test.cpp)
target_link_libraries(supervisor_path_exposure_test PRIVATE glove_supervisor)
add_test(NAME supervisor_path_exposure COMMAND supervisor_path_exposure_test)

add_executable(supervisor_path_exposure_journal_test supervisor/path_exposure_journal_test.cpp)
target_link_libraries(supervisor_path_exposure_journal_test PRIVATE glove_supervisor)
add_test(NAME supervisor_path_exposure_journal COMMAND supervisor_path_exposure_journal_test)

add_executable(supervisor_session_plan_test supervisor/session_plan_test.cpp)
target_link_libraries(supervisor_session_plan_test PRIVATE glove_supervisor)
add_test(NAME supervisor_session_plan COMMAND supervisor_session_plan_test)

add_executable(supervisor_library_bundle_test supervisor/library_bundle_test.cpp)
target_link_libraries(supervisor_library_bundle_test PRIVATE glove_supervisor)
add_test(NAME supervisor_library_bundle COMMAND supervisor_library_bundle_test)

add_executable(supervisor_change_manifest_test supervisor/change_manifest_test.cpp)
target_link_libraries(supervisor_change_manifest_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_manifest COMMAND supervisor_change_manifest_test)

add_executable(
    supervisor_change_apply_authorization_test
    supervisor/change_apply_authorization_test.cpp
)
target_link_libraries(supervisor_change_apply_authorization_test PRIVATE glove_supervisor)
add_test(
    NAME supervisor_change_apply_authorization
    COMMAND supervisor_change_apply_authorization_test
)

add_executable(supervisor_change_apply_journal_test supervisor/change_apply_journal_test.cpp)
target_link_libraries(supervisor_change_apply_journal_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_apply_journal COMMAND supervisor_change_apply_journal_test)

add_executable(
    supervisor_change_apply_trust_policy_test
    supervisor/change_apply_trust_policy_test.cpp
)
target_link_libraries(supervisor_change_apply_trust_policy_test PRIVATE glove_supervisor)
add_test(
    NAME supervisor_change_apply_trust_policy
    COMMAND supervisor_change_apply_trust_policy_test
)

add_executable(supervisor_change_apply_recovery_test supervisor/change_apply_recovery_test.cpp)
target_link_libraries(supervisor_change_apply_recovery_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_apply_recovery COMMAND supervisor_change_apply_recovery_test)

add_executable(supervisor_change_apply_gate_test supervisor/change_apply_gate_test.cpp)
target_link_libraries(supervisor_change_apply_gate_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_apply_gate COMMAND supervisor_change_apply_gate_test)

add_executable(supervisor_change_apply_exchange_test supervisor/change_apply_exchange_test.cpp)
target_link_libraries(supervisor_change_apply_exchange_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_apply_exchange COMMAND supervisor_change_apply_exchange_test)

add_executable(supervisor_change_apply_receipt_test supervisor/change_apply_receipt_test.cpp)
target_link_libraries(supervisor_change_apply_receipt_test PRIVATE glove_supervisor)
add_test(NAME supervisor_change_apply_receipt COMMAND supervisor_change_apply_receipt_test)

add_executable(kernel_registry_test kernel/registry_test.cpp)
target_link_libraries(kernel_registry_test PRIVATE glove_kernel)
add_test(NAME kernel_registry COMMAND kernel_registry_test)

add_executable(kernel_server_test kernel/server_test.cpp)
target_link_libraries(kernel_server_test PRIVATE glove_kernel)
target_include_directories(kernel_server_test PRIVATE $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}>)
add_test(NAME kernel_server COMMAND kernel_server_test)

add_executable(kernel_mcp_extension_test kernel/mcp_extension_test.cpp)
target_link_libraries(kernel_mcp_extension_test PRIVATE glove_kernel)
add_test(NAME kernel_mcp_extension COMMAND kernel_mcp_extension_test)

if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(
        mcp_stdio_transport_process_tree_test
        mcp/stdio_transport_process_tree_test.cpp
    )
    target_link_libraries(mcp_stdio_transport_process_tree_test PRIVATE glove_kernel)
    add_test(NAME mcp_stdio_transport_process_tree COMMAND mcp_stdio_transport_process_tree_test)
    set_tests_properties(mcp_stdio_transport_process_tree PROPERTIES TIMEOUT 10)

    add_executable(container_spawner_test container/spawner_test.cpp)
    target_link_libraries(container_spawner_test PRIVATE glove_kernel)
    target_compile_definitions(container_spawner_test PRIVATE
        GLOVE_SYNTHETIC_AGENT_BIN="$<TARGET_FILE:glove_synthetic_agent>")
    add_dependencies(container_spawner_test glove_synthetic_agent)
    add_test(NAME container_spawner COMMAND container_spawner_test)
    set_tests_properties(container_spawner PROPERTIES TIMEOUT 30)

    add_executable(glove_exec_perimeter_test run/glove_exec_perimeter_test.cpp)
    target_link_libraries(glove_exec_perimeter_test PRIVATE glove_kernel)
    target_compile_definitions(glove_exec_perimeter_test PRIVATE
        GLOVE_BIN="$<TARGET_FILE:glove>")
    add_dependencies(glove_exec_perimeter_test glove)
    add_test(NAME glove_exec_perimeter COMMAND glove_exec_perimeter_test)
    set_tests_properties(glove_exec_perimeter PROPERTIES TIMEOUT 30)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(
        control_linux_process_identity_test
        control/linux_process_identity_test.cpp
    )
    target_link_libraries(control_linux_process_identity_test PRIVATE glove_control)
    target_include_directories(control_linux_process_identity_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
    )
    add_test(NAME control_linux_process_identity COMMAND control_linux_process_identity_test)

    add_executable(
        control_receipt_audit_unix_server_test
        control/receipt_audit_unix_server_test.cpp
    )
    target_link_libraries(
        control_receipt_audit_unix_server_test
        PRIVATE glove_control glaze::glaze
    )
    target_include_directories(control_receipt_audit_unix_server_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
    )
    add_test(
        NAME control_receipt_audit_unix_server
        COMMAND control_receipt_audit_unix_server_test
    )
    set_tests_properties(control_receipt_audit_unix_server PROPERTIES TIMEOUT 10)

    add_executable(
        container_linux_launch_binding_test
        container/linux_launch_binding_test.cpp
    )
    target_link_libraries(container_linux_launch_binding_test PRIVATE glove_container)
    target_include_directories(container_linux_launch_binding_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    add_test(NAME container_linux_launch_binding COMMAND container_linux_launch_binding_test)

    add_executable(
        container_linux_pty_session_channel_test
        container/linux_pty_session_channel_test.cpp
    )
    target_link_libraries(container_linux_pty_session_channel_test PRIVATE glove_container)
    target_include_directories(container_linux_pty_session_channel_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    add_test(
        NAME container_linux_pty_session_channel
        COMMAND container_linux_pty_session_channel_test
    )
    set_tests_properties(container_linux_pty_session_channel PROPERTIES TIMEOUT 10)

    add_executable(
        supervisor_linux_ephemeral_copy_test
        supervisor/linux_ephemeral_copy_test.cpp
    )
    target_link_libraries(supervisor_linux_ephemeral_copy_test PRIVATE glove_supervisor)
    add_test(NAME supervisor_linux_ephemeral_copy COMMAND supervisor_linux_ephemeral_copy_test)
    set_tests_properties(supervisor_linux_ephemeral_copy PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    add_executable(
        supervisor_linux_session_filesystem_test
        supervisor/linux_session_filesystem_test.cpp
    )
    target_link_libraries(supervisor_linux_session_filesystem_test PRIVATE glove_supervisor)
    add_test(NAME supervisor_linux_session_filesystem COMMAND supervisor_linux_session_filesystem_test)
    set_tests_properties(supervisor_linux_session_filesystem PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    # Deliberately exclude sanitizer runtimes: pids.max counts threads, so the
    # pressure shape must not change between ASan, TSan, and release lanes.
    add_executable(glove_cgroup_probe_agent container/cgroup_probe_agent.cpp)
    target_compile_features(glove_cgroup_probe_agent PRIVATE cxx_std_23)
    glove_set_warnings(glove_cgroup_probe_agent)

    add_executable(container_linux_cgroup_v2_test container/linux_cgroup_v2_test.cpp)
    target_link_libraries(container_linux_cgroup_v2_test PRIVATE glove_container)
    target_include_directories(container_linux_cgroup_v2_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    target_compile_definitions(container_linux_cgroup_v2_test PRIVATE
        GLOVE_CGROUP_PROBE_AGENT_BIN="$<TARGET_FILE:glove_cgroup_probe_agent>"
    )
    add_dependencies(container_linux_cgroup_v2_test glove_cgroup_probe_agent)
    add_test(NAME container_linux_cgroup_v2 COMMAND container_linux_cgroup_v2_test)
    set_tests_properties(container_linux_cgroup_v2 PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    add_executable(
        container_linux_resource_lifecycle_test
        container/linux_resource_lifecycle_test.cpp
    )
    target_link_libraries(container_linux_resource_lifecycle_test PRIVATE glove_container)
    target_include_directories(container_linux_resource_lifecycle_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    target_compile_definitions(container_linux_resource_lifecycle_test PRIVATE
        GLOVE_CGROUP_PROBE_AGENT_BIN="$<TARGET_FILE:glove_cgroup_probe_agent>"
    )
    add_dependencies(container_linux_resource_lifecycle_test glove_cgroup_probe_agent)
    add_test(NAME container_linux_resource_lifecycle COMMAND container_linux_resource_lifecycle_test)
    set_tests_properties(container_linux_resource_lifecycle PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    add_executable(
        container_linux_managed_session_test
        container/linux_managed_session_test.cpp
    )
    target_link_libraries(container_linux_managed_session_test PRIVATE glove_container)
    target_include_directories(container_linux_managed_session_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    add_test(NAME container_linux_managed_session COMMAND container_linux_managed_session_test)
    set_tests_properties(container_linux_managed_session PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    add_executable(
        control_linux_session_preparation_test
        control/linux_session_preparation_test.cpp
    )
    target_link_libraries(control_linux_session_preparation_test PRIVATE glove_control)
    target_include_directories(control_linux_session_preparation_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    add_test(
        NAME control_linux_session_preparation
        COMMAND control_linux_session_preparation_test
    )
    set_tests_properties(control_linux_session_preparation PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    add_executable(
        control_linux_session_executor_test
        control/linux_session_executor_test.cpp
    )
    target_link_libraries(
        control_linux_session_executor_test
        PRIVATE glove_control glaze::glaze
    )
    target_include_directories(control_linux_session_executor_test PRIVATE
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/control>
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src/container/linux>
    )
    add_test(
        NAME control_linux_session_executor
        COMMAND control_linux_session_executor_test
    )
    set_tests_properties(control_linux_session_executor PROPERTIES
        TIMEOUT 30
        SKIP_RETURN_CODE 77
    )

    # Stage 3 (Linux): `glove exec` clone-child stdio-passthrough contain path.
    # Needs the privileged clone3 + pivot_root environment.
    add_executable(container_linux_exec_test container/linux_exec_test.cpp)
    target_link_libraries(container_linux_exec_test PRIVATE glove_kernel)
    add_test(NAME container_linux_exec COMMAND container_linux_exec_test)
    set_tests_properties(container_linux_exec PROPERTIES TIMEOUT 30)
endif()

add_executable(reflect_codegen_availability_test reflect/codegen_availability_test.cpp)
target_link_libraries(reflect_codegen_availability_test PRIVATE glove_kernel)
add_test(NAME reflect_codegen_availability COMMAND reflect_codegen_availability_test)

if(APPLE)
    add_executable(mcp_stdio_transport_test mcp/stdio_transport_test.cpp)
    target_link_libraries(mcp_stdio_transport_test PRIVATE glove_kernel)
    add_test(NAME mcp_stdio_transport COMMAND mcp_stdio_transport_test)

    # Stage 1: the spawner contains an arbitrary binary via SBPL (writes outside
    # the workspace denied, inside allowed). macOS-only (sandbox-exec).
    add_executable(container_macos_sandbox_test container/macos_sandbox_test.cpp)
    target_link_libraries(container_macos_sandbox_test PRIVATE glove_kernel)
    add_test(NAME container_macos_sandbox COMMAND container_macos_sandbox_test)
    set_tests_properties(container_macos_sandbox PROPERTIES TIMEOUT 30)

    # Stage 3: `glove exec` stdio-passthrough contain path (HOME→workspace,
    # writes outside denied). macOS-only.
    add_executable(container_macos_exec_test container/macos_exec_test.cpp)
    target_link_libraries(container_macos_exec_test PRIVATE glove_kernel)
    add_test(NAME container_macos_exec COMMAND container_macos_exec_test)
    set_tests_properties(container_macos_exec PROPERTIES TIMEOUT 30)

    add_executable(glove_exec_audit_test run/glove_exec_audit_test.cpp)
    target_link_libraries(glove_exec_audit_test PRIVATE glove_kernel)
    target_compile_definitions(glove_exec_audit_test PRIVATE
        GLOVE_BIN="$<TARGET_FILE:glove>")
    add_dependencies(glove_exec_audit_test glove)
    add_test(NAME glove_exec_audit COMMAND glove_exec_audit_test)
    set_tests_properties(glove_exec_audit PROPERTIES TIMEOUT 30)
endif()

# F1 regression: upstream pipe fds must be close-on-exec so they cannot leak
# into a later-spawned (contained) process. Cross-platform: needs /bin/sh,
# /bin/cat, and /dev/fd, all present on macOS and Linux.
if(APPLE OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(mcp_stdio_transport_cloexec_test mcp/stdio_transport_cloexec_test.cpp)
    target_link_libraries(mcp_stdio_transport_cloexec_test PRIVATE glove_kernel)
    add_test(NAME mcp_stdio_transport_cloexec COMMAND mcp_stdio_transport_cloexec_test)
    set_tests_properties(mcp_stdio_transport_cloexec PROPERTIES TIMEOUT 30)

    # F4 regression: an unbounded newline-less stream must be rejected, not
    # buffered until OOM.
    add_executable(mcp_stdio_transport_frame_cap_test mcp/stdio_transport_frame_cap_test.cpp)
    target_link_libraries(mcp_stdio_transport_frame_cap_test PRIVATE glove_kernel)
    add_test(NAME mcp_stdio_transport_frame_cap COMMAND mcp_stdio_transport_frame_cap_test)
    set_tests_properties(mcp_stdio_transport_frame_cap PROPERTIES TIMEOUT 30)
endif()

# Real-server smoke against yams; opt-in based on yams being on PATH at
# configure time. Sanitizers may slow the spawn, so the test gets a generous
# 30s timeout.
find_program(GLOVE_YAMS_BIN yams)
if(GLOVE_YAMS_BIN)
    add_executable(mcp_yams_smoke_test mcp/yams_smoke_test.cpp)
    target_link_libraries(mcp_yams_smoke_test PRIVATE glove_kernel)
    target_compile_definitions(mcp_yams_smoke_test PRIVATE
        GLOVE_YAMS_BIN="${GLOVE_YAMS_BIN}")
    add_test(NAME mcp_yams_smoke COMMAND mcp_yams_smoke_test)
    set_tests_properties(mcp_yams_smoke PROPERTIES TIMEOUT 30)

    add_executable(mcp_yams_call_test mcp/yams_call_test.cpp)
    target_link_libraries(mcp_yams_call_test PRIVATE glove_kernel)
    target_compile_definitions(mcp_yams_call_test PRIVATE
        GLOVE_YAMS_BIN="${GLOVE_YAMS_BIN}")
    add_test(NAME mcp_yams_call COMMAND mcp_yams_call_test)
    set_tests_properties(mcp_yams_call PROPERTIES TIMEOUT 30)

    add_executable(mcp_yams_annotations_test mcp/yams_annotations_test.cpp)
    target_link_libraries(mcp_yams_annotations_test PRIVATE glove_kernel)
    target_compile_definitions(mcp_yams_annotations_test PRIVATE
        GLOVE_YAMS_BIN="${GLOVE_YAMS_BIN}")
    add_test(NAME mcp_yams_annotations COMMAND mcp_yams_annotations_test)
    set_tests_properties(mcp_yams_annotations PROPERTIES TIMEOUT 30)

    add_executable(glove_run_yams_test run/glove_run_yams_test.cpp)
    target_link_libraries(glove_run_yams_test PRIVATE glove_kernel)
    target_compile_definitions(glove_run_yams_test PRIVATE
        GLOVE_BIN="$<TARGET_FILE:glove>"
        GLOVE_SYNTHETIC_AGENT_BIN="$<TARGET_FILE:glove_synthetic_agent>"
        GLOVE_YAMS_BIN="${GLOVE_YAMS_BIN}")
    add_dependencies(glove_run_yams_test glove glove_synthetic_agent)
    add_test(NAME glove_run_yams COMMAND glove_run_yams_test)
    set_tests_properties(glove_run_yams PROPERTIES TIMEOUT 30)

    add_executable(glove_run_arg_rule_test run/glove_run_arg_rule_test.cpp)
    target_link_libraries(glove_run_arg_rule_test PRIVATE glove_kernel)
    target_compile_definitions(glove_run_arg_rule_test PRIVATE
        GLOVE_BIN="$<TARGET_FILE:glove>"
        GLOVE_SYNTHETIC_AGENT_BIN="$<TARGET_FILE:glove_synthetic_agent>"
        GLOVE_YAMS_BIN="${GLOVE_YAMS_BIN}")
    add_dependencies(glove_run_arg_rule_test glove glove_synthetic_agent)
    add_test(NAME glove_run_arg_rule COMMAND glove_run_arg_rule_test)
    set_tests_properties(glove_run_arg_rule PROPERTIES TIMEOUT 60)

    message(STATUS "  yams smoke/call/annotations : enabled (${GLOVE_YAMS_BIN})")
else()
    message(STATUS "  yams smoke test       : disabled (yams not on PATH)")
endif()
