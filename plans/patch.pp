plan os_patching::patch (TargetSpec $nodes) {
  run_task("os_patching::patch_server", $nodes)
}
