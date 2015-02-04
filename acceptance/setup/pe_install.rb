test_name "Install ACL Module on Master"

step "Install PE"
install_pe

step "Install Module hosts"
proj_root = File.expand_path(File.join(File.dirname(__FILE__), '../..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, :source => proj_root, :module_name => 'acl')
end


step "Plug-in Sync Each Agent"
with_puppet_running_on master, :main => { :verbose => true, :daemonize => true } do
  on agents, puppet("plugin download --server #{master}")
end
