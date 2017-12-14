require 'spec_helper_acceptance'

describe 'Purge' do

  def acl_manifest(target, file_content)
    return <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      
      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }
      
      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
      
      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def purge_acl_manifest(target)
    return <<-MANIFEST
      acl { "#{target}":
        purge        => 'true',
        permissions  => [],
        inherit_parent_permissions => 'false'
      }
    MANIFEST
  end

  context 'Negative - Purge Absolutely All Permissions from File without Inheritance' do
    target = "#{target_parent}/purge_all_no_inherit.txt"
    file_content = 'Breakfast is the most important meal of the day.'
    verify_content_command = "cat /cygdrive/c/temp/purge_all_no_inherit.txt"
    verify_acl_command = "icacls #{target}"
    acl_regex_user_id = /.*\\bob:\(F\)/

    verify_purge_error = /Error:.*Value for permissions should be an array with at least one element specified/

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute Apply Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => acl_manifest(target, file_content)) do |result|
            assert_no_match(/Error:/, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(acl_regex_user_id, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Attempt to Execute Purge Manifest' do
          on(agent, puppet('apply', '--debug'), :stdin => purge_acl_manifest(target), :acceptable_exit_codes => [1]) do |result|
            assert_match(verify_purge_error, result.stderr, 'Expected error was not detected!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            assert_match(file_content_regex(file_content), result.stdout, 'Expected file content is invalid!')
          end
        end
      end
    end
  end
end
