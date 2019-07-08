require 'spec_helper_acceptance'

describe 'Negative - Specify Symlink as Target' do
  os_check_command = 'cmd /c ver'
  os_check_regex = %r{Version 5}

  target = 'c:/temp/sym_target_file.txt'
  target_symlink = 'c:/temp/symlink'

  file_content = 'A link to the past.'
  verify_content_command = 'cat /cygdrive/c/temp/sym_target_file.txt'

  win_target = 'c:\\temp\\sym_target_file.txt'
  win_target_symlink = 'c:\\temp\\symlink'
  mklink_command = "c:\\windows\\system32\\cmd.exe /c mklink #{win_target_symlink} #{win_target}"

  verify_acl_command = "icacls #{target_symlink}"
  acl_regex = %r{.*\\bob:\(F\)}

  acl_manifest = <<-MANIFEST
    file { "#{target_parent}":
      ensure => directory
    }

    file { '#{target}':
      ensure  => file,
      content => '#{file_content}',
      require => File['#{target_parent}']
    }

    user { "#{user_id}":
      ensure     => present,
      groups     => 'Users',
      managehome => true,
      password   => "L0v3Pupp3t!",
      require => File['#{target}']
    }

    exec { 'Create Windows Symlink':
      command => '#{mklink_command}',
      creates => '#{target_symlink}',
      cwd     => '#{target_parent}',
      require => User['#{user_id}']
    }

    acl { "#{target_symlink}":
      permissions  => [
        { identity => '#{user_id}', rights => ['full'] },
      ],
      require      => Exec['Create Windows Symlink']
    }
  MANIFEST

  windows_agents.each do |agent|
    context "on #{agent}" do
      # Determine if running on Windows 2003.
      # Skip if 2003 since MKLINK is not available.
      it 'Determine OS Type' do
        on(agent, os_check_command) do |result|
          if os_check_regex =~ result.stdout
            skip_test('This test cannot run on a Windows 2003 system!')
          end
        end
      end

      it 'Execute Manifest' do
        execute_manifest_on(agent, acl_manifest, debug: true) do |result|
          expect(result.stderr).not_to match(%r{Error:})
        end
      end

      it 'Verify that ACL Rights are Correct' do
        on(agent, verify_acl_command) do |result|
          expect(result.stderr).not_to match(%r{#{acl_regex}})
        end
      end

      it 'Verify File Data Integrity' do
        on(agent, verify_content_command) do |result|
          expect(result.stdout).to match(%r{#{file_content_regex(file_content)}})
        end
      end
    end
  end
end
