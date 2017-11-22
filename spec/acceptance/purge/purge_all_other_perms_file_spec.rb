require 'spec_helper_acceptance'

describe 'Purge' do

  def acl_manifest(target, file_content, user_id_1, user_id_2)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }
      
      user { "#{user_id_1}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      user { "#{user_id_2}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id_1}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def purge_acl_manifest(target, user_id_2)
    return <<-MANIFEST
      acl { "#{target}":
        purge        => 'true',
        permissions  => [
          { identity => '#{user_id_2}', rights => ['full'] },
        ],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'Purge All Other Permissions from File without Inheritance' do
    target = "#{target_parent}/purge_all_other_no_inherit.txt"
    user_id_1 = 'bob'
    user_id_2 = 'jerry'

    file_content = 'All your base are belong to us.'

    verify_acl_command = "icacls #{target}"
    acl_regex_user_id_1 = /.*\\bob:\(F\)/

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Apply Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, file_content, user_id_1, user_id_2)) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(acl_regex_user_id_1, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Execute Purge Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => purge_acl_manifest(target, user_id_2)) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end
      end
    end
  end
end
