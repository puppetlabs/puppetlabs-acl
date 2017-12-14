require 'spec_helper_acceptance'

describe 'Purge' do

  def acl_manifest(target, user_id_1, user_id_2)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target}":
        ensure  => directory,
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

  context 'Purge All Other Permissions from Directory without Inheritance' do
    os_check_command = 'cmd /c ver'
    os_check_regex = /Version 5/
    os_version_win_2003 = false

    target = "#{target_parent}/purge_all_other_no_inherit"
    user_id_1 = 'bob'
    user_id_2 = generate_random_username

    verify_acl_command = "icacls #{target}"
    acl_regex_user_id_1 = /.*\\bob:\(OI\)\(CI\)\(F\)/
    acl_regex_user_id_2 = /\Ac:\/temp\/purge_all_other_no_inherit.*\\#{user_id_2}:\(OI\)\(CI\)\(F\)\n\nSuccessfully/
    acl_regex_win_2003 = /c:\/temp\/purge_all_other_no_inherit: Access is denied\./

    windows_agents.each do |agent|
      context "Determine OS Type on #{agent}" do
        on(agent, os_check_command) do |result|
          if os_check_regex =~ result.stdout
            os_version_win_2003 = true
          end
        end

        it 'Execute Apply Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, user_id_1, user_id_2)) do |result|
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

        it 'Verify that ACL Rights are Correct (Post-Purge)' do
          on(agent, verify_acl_command, :acceptable_exit_codes => [0,5]) do |result|
            if os_version_win_2003
              assert_match(acl_regex_win_2003, result.stderr, 'Expected failure was not present!')
            else
              assert_no_match(acl_regex_user_id_1, result.stdout, 'Unexpected ACL was present!')
              assert_match(acl_regex_user_id_2, result.stdout, 'Expected ACL was not present!')
            end
          end
        end
      end
    end
  end
end
