require 'beaker/puppet_install_helper'

run_puppet_install_helper

step "Install Module hosts"
proj_root = File.expand_path(File.join(File.dirname(__FILE__), '../..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, :source => proj_root, :module_name => 'acl')
end
