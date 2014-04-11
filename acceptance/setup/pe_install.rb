test_name "Install ACL Module on Master"

step "Install PE"
install_pe
  
step "Clone Git Repo"
on master, "git clone https://github.com/cowofevil/puppetlabs-acl.git /etc/puppetlabs/puppet/modules/acl"

step "Plug-in Sync Each Agent"
with_puppet_running_on master, :main => { :verbose => true, :daemonize => true } do
  on agents, puppet("plugin download --server #{master}")
end
