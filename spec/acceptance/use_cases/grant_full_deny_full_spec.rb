require 'spec_helper_acceptance'

describe 'Use Cases' do
  def acl_manifest(target, target_child, file_content, group, user_id)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure => directory,
        require => File['#{target_parent}']
      }

      file { "#{target_child}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target}']
      }

      acl { "#{target}":
        permissions  => [
          { identity => '#{group}',type => 'allow', rights => ['full'] },
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id}',type => 'deny', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  def update_manifest(target_child)
    <<-MANIFEST
      file { "#{target_child}":
        ensure  => file,
        content => 'Better Content'
      }
    MANIFEST
  end

  context "Inherit 'full' Rights for User's Group on Container and Deny User 'full' Rights on Object in Container" do
    test_short_name = 'grant_full_deny_full'
    file_content = 'Sad people'
    target_name = "use_case_#{test_short_name}"
    target_child_name = "use_case_child_#{test_short_name}.txt"
    target = "#{target_parent}/#{target_name}"
    target_child = "#{target}/#{target_child_name}"
    verify_content_command = "cat /cygdrive/c/temp/#{target_name}/#{target_child_name}"
    group = 'Administrators'
    user_id = 'Administrator'
    verify_acl_child_command = "icacls #{target_child}"
    target_child_first_ace_regex = %r{.*\\Administrators:\(I\)\(F\)}
    target_child_second_ace_regex = %r{.*\\Administrator:\(N\)}

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target, target_child, file_content, group, user_id), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct for Child' do
          on(agent, verify_acl_child_command) do |result|
            assert_match(target_child_first_ace_regex, result.stdout, 'Expected ACL was not present!')
            assert_match(target_child_second_ace_regex, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Attempt to Update File' do
          execute_manifest_on(agent, update_manifest(target_child), { :debug => true }) do |result|
            assert_match(%r{Error:}, result.stderr, 'Expected error was not detected!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            assert_match(file_content_regex(file_content), result.stdout, 'File content is invalid!')
          end
        end
      end
    end
  end
end
