require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
  context "on #{agent}" do
    it 'Execute Manifest' do
      on(agent, puppet('apply', '--debug'), stdin: acl_manifest(target, rights, file_content)) do |result|
        assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
      end
    end

    it 'Verify that ACL Rights are Correct' do
      on(agent, verify_acl_command(target)) do |result|
        assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
      end
    end

    it 'Verify File Data Integrity' do
      on(agent, verify_content_command(target)) do |result|
        assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
      end
    end
  end
end

describe 'File - Allow' do
  def acl_manifest(target, rights, file_content)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target}':
        ensure  => file,
        content => '#{file_content}',
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

  def verify_content_command(target)
    target = target[3..-1] # remove the leading 'c:/' from the target
    "cat /cygdrive/c/#{target}"
  end

  def verify_acl_command(target)
    "icacls #{target}"
  end

  context '"execute" Rights for Identity on File' do
    rights = 'execute'
    target = "c:/temp/allow_#{rights}_rights_file.txt"
    file_content = 'The bed that eats people. DEATH BED!'
    acl_regex = %r{.*\\bob:\(Rc,S,X,RA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"modify" Rights for Identity on File' do
    rights = 'modify'
    target = "c:/temp/allow_#{rights}_rights_file.txt"
    file_content = 'Snow on the bluff.'
    acl_regex = %r{.*\\bob:\(M\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"read, execute" Rights for Identity on File' do
    rights = "read','execute"
    target = 'c:/temp/allow_re_rights_file.txt'
    file_content = 'Get on the phone with baked beans!'
    acl_regex = %r{.*\\bob:\(RX\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"read" Rights for Identity on File' do
    rights = 'read'
    target = "c:/temp/allow_#{rights}_rights_file.txt"
    file_content = 'Deadly couch eating monster.'
    acl_regex = %r{.*\\bob:\(R\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, execute" Rights for Identity on File' do
    rights = "write','execute"
    target = 'c:/temp/allow_we_rights_file.txt'
    file_content = 'Get on the phone with baked beans!'
    acl_regex = %r{.*\\bob:\(W,Rc,X,RA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, read" Rights for Identity on File' do
    rights = "write','read"
    target = 'c:/temp/allow_wr_rights_file.txt'
    file_content = 'Mushy bean paste in my eyes!'
    acl_regex = %r{.*\\bob:\(R,W\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, read, execute" Rights for Identity on File' do
    rights = "write','read','execute"
    target = 'c:/temp/allow_wre_rights_file.txt'
    file_content = 'Very small feet to eat.'
    acl_regex = %r{.*\\bob:\(RX,W\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write" Rights for Identity on File' do
    rights = 'write'
    target = "c:/temp/allow_#{rights}_rights_file.txt"
    file_content = 'Smart bubbles in my bath.'
    acl_regex = %r{.*\\bob:\(W,Rc\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
