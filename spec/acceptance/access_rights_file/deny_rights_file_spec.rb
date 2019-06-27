require 'spec_helper_acceptance'

# rubocop:disable RSpec/EmptyExampleGroup
def apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
  context "on #{agent}" do
    it 'Execute Manifest' do
      execute_manifest_on(agent, acl_manifest(target, rights, file_content), debug: true) do |result|
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

describe 'File - Deny' do
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
          { identity => '#{user_id}', perm_type => 'deny', rights => ['#{rights}'] },
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
    file_content = 'Smells like teen spirit or body odor.'
    target = "c:/temp/deny_#{rights}_rights_file.txt"
    acl_regex = %r{.*\\bob:\(DENY\)\(Rc,S,X,RA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"full" Rights for Identity on File' do
    rights = 'full'
    target = "c:/temp/deny_#{rights}_rights_file.txt"
    file_content = 'You have to fight for your right to party.'
    acl_regex = %r{.*\\bob:\(N\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"modify" Rights for Identity on File' do
    rights = 'modify'
    target = "c:/temp/deny_#{rights}_rights_file.txt"
    file_content = 'Giant flying space pigs with lasers.'
    acl_regex = %r{.*\\bob:\(DENY\)\(M\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"read, execute" Rights for Identity on File' do
    rights = "read','execute"
    target = 'c:/temp/deny_re_rights_file.txt'
    file_content = 'Your forcefield is good, but my teleporting is better.'
    acl_regex = %r{.*\\bob:\(DENY\)\(RX\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"read" Rights for Identity on File' do
    rights = 'read'
    target = "c:/temp/deny_#{rights}_rights_file.txt"
    file_content = 'Elvis is king of rock and roll.'
    acl_regex = %r{.*\\bob:\(DENY\)\(R\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, execute" Rights for Identity on File' do
    rights = "write','execute"
    target = 'c:/temp/deny_we_rights_file.txt'
    file_content = 'Now time for some rocket fuel.'
    acl_regex = %r{.*\\bob:\(DENY\)\(W,Rc,X,RA\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, read" Rights for Identity on File' do
    rights = "write','read"
    target = 'c:/temp/deny_wr_rights_file.txt'
    file_content = 'I live in a garbage can.'
    acl_regex = %r{.*\\bob:\(DENY\)\(R,W\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write, read, execute" Rights for Identity on File' do
    rights = "write','read','execute"
    target = 'c:/temp/deny_wre_rights_file.txt'
    file_content = 'Flying rats.'
    acl_regex = %r{.*\\bob:\(DENY\)\(RX,W\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end

  context '"write" Rights for Identity on File' do
    rights = 'write'
    target = "c:/temp/deny_#{rights}_rights_file.txt"
    file_content = 'Marxist cat wants some of your food.'
    acl_regex = %r{.*\\bob:\(DENY\)\(W,Rc\)}

    windows_agents.each do |agent|
      apply_manifest_and_verify(acl_regex, agent, file_content, rights, target)
    end
  end
end
# rubocop:enable RSpec/EmptyExampleGroup
