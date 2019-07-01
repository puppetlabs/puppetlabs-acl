require 'spec_helper_acceptance'
require 'pry-byebug'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_with_rights(acl_regex, agent, rights, target)
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(target, rights), { :debug => true }) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(target)) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end
  end
end

describe 'Directory - Allow' do
  def acl_manifest(target, rights)
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
          { identity => '#{user_id}', perm_type => 'allow', rights => ['#{rights}'] },
        ],
      }
    MANIFEST
  end

  def verify_acl_command(target)
    "icacls #{target}"
  end

  context '"execute" Rights for Identity on Directory' do
    rights = 'execute'
    target = "c:/temp/allow_#{rights}_rights_dir"
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(Rc,S,X,RA\)}

    windows_agents.each do |agent|
      binding.pry
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"modify" Rights for Identity on Directory' do
    rights = 'modify'
    target = "c:/temp/allow_#{rights}_rights_dir"
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(M\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"read, execute" Rights for Identity on Directory' do
    rights = "read', 'execute"
    target = 'c:/temp/allow_re_rights_dir'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(RX\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"read" Rights for Identity on Directory' do
    rights = 'read'
    target = "c:/temp/allow_#{rights}_rights_dir"
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(R\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"write, execute" Rights for Identity on Directory' do
    rights = "write','execute"
    target = 'c:/temp/allow_we_rights_dir'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(W,Rc,X,RA\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"write, read" Rights for Identity on Directory' do
    rights = "write','read"
    target = 'c:/temp/allow_wr_rights_dir'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(R,W\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"write, read, execute" Rights for Identity on Directory' do
    rights = "write','read','execute"
    target = 'c:/temp/allow_wre_rights_dir'
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(RX,W\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end

  context '"write" Rights for Identity on Directory' do
    rights = 'write'
    target = "c:/temp/allow_#{rights}_rights_dir"
    acl_regex = %r{.*\\bob:\(OI\)\(CI\)\(W,Rc\)}

    windows_agents.each do |agent|
      apply_manifest_with_rights(acl_regex, agent, rights, target)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
