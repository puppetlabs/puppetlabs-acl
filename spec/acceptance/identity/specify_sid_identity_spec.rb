require 'spec_helper_acceptance'

describe 'Module - Identity' do
  def setup_manifest(target_file, file_content)
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { '#{target_parent}/#{target_file}':
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
    MANIFEST
  end

  def acl_manifest(target_file, sid)
    <<-MANIFEST
      acl { '#{target_parent}/#{target_file}':
        permissions => [
          { identity => '#{sid}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Specify SID Identity' do
    os_check_command = 'cmd /c ver'
    os_check_regex = %r{Version 5}
    target_file = 'specify_sid_ident.txt'
    file_content = 'Magic unicorn rainbow madness!'
    verify_content_command = "cat /cygdrive/c/temp/#{target_file}"
    get_user_sid_command = <<-GETSID
    cmd /c "wmic useraccount where name='#{user_id}' get sid"
    GETSID

    sid_regex = %r{^(S-.+)$}

    verify_acl_command = "icacls #{target_parent}/#{target_file}"
    acl_regex = %r{.*\\bob:\(F\)}
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
          execute_manifest_on(agent, setup_manifest(target_file, file_content), debug: true) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Get SID of User Account' do
          on(agent, get_user_sid_command) do |result|
            sid = sid_regex.match(result.stdout)[1]
          end
        end

        it 'Execute ACL Manifest' do
          execute_manifest_on(agent, acl_manifest(target_file, sid), debug: true) do |result|
            assert_no_match(%r{Error:}, result.stderr, 'Unexpected error was detected!')
          end
        end

        it 'Verify that ACL Rights are Correct' do
          on(agent, verify_acl_command) do |result|
            assert_match(acl_regex, result.stdout, 'Expected ACL was not present!')
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
