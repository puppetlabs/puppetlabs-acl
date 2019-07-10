require 'spec_helper_acceptance'

describe 'Directory - Deny' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { '#{target}':
        permissions  => [
          { identity => '#{user_id}', rights => ['#{rights}'], perm_type => 'deny' },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls #{target}" }

  context '"execute" Rights for Identity on Directory' do
    let(:rights) { 'execute' }
    let(:target) { "c:/temp/deny_#{rights}_rights_dir" }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(Rc,S,X,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"full" Rights for Identity on Directory' do
    let(:rights) { 'full' }
    let(:target) { "c:/temp/deny_#{rights}_rights_dir" }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(N\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"modify" Rights for Identity on Directory' do
    let(:rights) { 'modify' }
    let(:target) { "c:/temp/deny_#{rights}_rights_dir" }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(M\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"read, execute" Rights for Identity on Directory' do
    let(:rights) { "read', 'execute" }
    let(:target) { 'c:/temp/deny_re_rights_dir' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(RX\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"read" Rights for Identity on Directory' do
    let(:rights) { 'read' }
    let(:target) { "c:/temp/deny_#{rights}_rights_dir" }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(R\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"write, execute" Rights for Identity on Directory' do
    let(:rights) { "write','execute" }
    let(:target) { 'c:/temp/deny_we_rights_dir' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(W,Rc,X,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"write, read" Rights for Identity on Directory' do
    let(:rights) { "write','read" }
    let(:target) { 'c:/temp/deny_wr_rights_dir' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(R,W\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"write, read, execute" Rights for Identity on Directory' do
    let(:rights) { "write','read','execute" }
    let(:target) { 'c:/temp/deny_wre_rights_dir' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(RX,W\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"write" Rights for Identity on Directory' do
    let(:rights) { 'write' }
    let(:target) { "c:/temp/deny_#{rights}_rights_dir" }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(W,Rc\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end
end
