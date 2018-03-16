require 'spec_helper_acceptance'

describe 'Group - SID' do
  def setup_manifest(target_parent, target, file_content, user_id, group_id)
    <<-MANIFEST
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

      user { "#{group_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
    MANIFEST
  end

  def acl_manifest(target, user_id, sid)
    <<-MANIFEST
        acl { "#{target}":
          purge           => 'true',
          permissions     => [
            { identity    => 'CREATOR GROUP',
              rights      => ['modify']
            },
            { identity    => '#{user_id}',
              rights      => ['read']
            },
            { identity    => 'Administrators',
              rights      => ['full'],
              affects     => 'all',
              child_types => 'all'
            }
          ],
          group           => '#{sid}',
          inherit_parent_permissions => 'false'
        }
    MANIFEST
  end

  context 'Change Group to Local User SID' do
    os_check_command = 'cmd /c ver'
    os_check_regex = %r{Version 5}

    user_type = 'local_user_sid'
    file_content = 'Hot eyes in your sand!'

    parent_name = 'temp'
    target_name = "group_#{user_type}.txt"

    target_parent = "c:/#{parent_name}"
    target = "#{target_parent}/#{target_name}"
    user_id = 'bob'
    group_id = 'tom'

    get_group_sid_command = <<-GETSID
    cmd /c "wmic useraccount where name='#{group_id}' get sid"
    GETSID

    sid_regex = %r{^(S-.+)$}

    verify_content_command = "cat /cygdrive/c/#{parent_name}/#{target_name}"
    file_content_regex = %r{\A#{file_content}\z}

    verify_group_command = "icacls #{target}"
    group_regex = %r{.*\\tom:\(M\)}
    sid = ''

    windows_agents.each do |agent|
      context "on #{agent}" do
        it 'Determine OS Type' do
          on(agent, os_check_command) do |result|
            if os_check_regex =~ result.stdout
              skip_test('This test cannot run on a Windows 2003 system!')
            end
          end
        end

        it 'Execute Setup Manifest' do
          execute_manifest_on(agent, setup_manifest(target_parent, target, file_content, user_id, group_id), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Get SID of User Account' do
          on(agent, get_group_sid_command) do |result|
            sid = sid_regex.match(result.stdout)[1]
          end
        end

        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target, user_id, sid), { :debug => true }) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_group_command) do |result|
            assert_match(group_regex, result.stdout, 'Expected ACL was not present!')
          end
        end

        it 'Verify File Data Integrity' do
          on(agent, verify_content_command) do |result|
            assert_match(file_content_regex, result.stdout, 'File content is invalid!')
          end
        end
      end
    end
  end
end
