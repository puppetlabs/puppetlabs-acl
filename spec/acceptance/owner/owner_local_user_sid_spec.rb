require 'spec_helper_acceptance'

describe 'Owner - SID' do
  def setup_manifest(target_name, file_content, owner_id)
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target_parent}/#{target_name}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
      }

      user { "#{owner_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }
    MANIFEST
  end

  def acl_manifest(target_name, sid)
    <<-MANIFEST
      acl { "#{target_parent}/#{target_name}":
        permissions  => [
          { identity => '#{user_id}',
            rights   => ['modify']
          },
        ],
        owner        => '#{sid}'
      }
    MANIFEST
  end

  context 'Change Owner to Local User SID' do
    os_check_command = 'cmd /c ver'
    os_check_regex = %r{Version 5}
    file_content = 'Rocket ship to the moon!'
    target_name = 'owner_local_user_sid.txt'
    owner_id = 'geraldo'

    get_owner_sid_command = <<-GETSID
    cmd /c "wmic useraccount where name='#{owner_id}' get sid"
    GETSID

    sid_regex = %r{^(S-.+)$}

    verify_content_command = "cat /cygdrive/c/temp/#{target_name}"
    file_content_regex = %r{\A#{file_content}\z}

    dosify_target = "c:\\temp\\#{target_name}"
    verify_owner_command = "cmd /c \"dir /q #{dosify_target}\""
    owner_regex = %r{.*\\#{owner_id}}

    windows_agents.each do |agent|
      context "on #{agent}" do
        sid = ''
        it 'Determine OS Type' do
          on(agent, os_check_command) do |result|
            if os_check_regex =~ result.stdout
              skip_test('This test cannot run on a Windows 2003 system!')
            end
          end
        end

        it 'Execute Setup Manifest' do
          on(agent, puppet('apply', '--debug'), stdin: setup_manifest(target_name, file_content, owner_id)) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Get SID of User Account' do
          on(agent, get_owner_sid_command) do |result|
            sid = sid_regex.match(result.stdout)[1]
          end
        end

        it 'Execute ACL Manifest' do
          on(agent, puppet('apply', '--debug'), stdin: acl_manifest(target_name, sid)) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_owner_command) do |result|
            assert_match(owner_regex, result.stdout, 'Expected ACL was not present!')
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
