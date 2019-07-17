require 'beaker-pe'
require 'beaker-puppet'
require 'beaker-rspec'
require 'beaker/puppet_install_helper'
require 'beaker/module_install_helper'
require 'beaker/testmode_switcher'
require 'beaker/testmode_switcher/dsl'
require 'spec_helper_acceptance_local' if File.file?(File.join(File.dirname(__FILE__), 'spec_helper_acceptance_local.rb'))

run_puppet_install_helper
configure_type_defaults_on(hosts)

install_ca_certs

proj_root = File.expand_path(File.join(File.dirname(__FILE__), '..'))
hosts.each do |host|
  install_dev_puppet_module_on(host, source: proj_root, module_name: 'acl')
end
