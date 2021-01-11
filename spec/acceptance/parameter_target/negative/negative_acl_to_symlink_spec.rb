# frozen_string_literal: true

require 'spec_helper_acceptance'

describe 'Negative - Specify Symlink as Target' do
  let(:os_check_command) { 'cmd /c ver' }
  let(:os_check_regex) { %r{Version 5} }

  let(:target) { 'c:/temp/sym_target_file.txt' }
  let(:target_symlink) { 'c:/temp/symlink' }

  let(:file_content) { 'A link to the past.' }
  let(:verify_content_path) { "#{target_parent}/sym_target_file.txt" }

  let(:win_target) { 'c:\\temp\\sym_target_file.txt' }
  let(:win_target_symlink) { 'c:\\temp\\symlink' }
  let(:mklink_command) { "c:\\windows\\system32\\cmd.exe /c mklink #{win_target_symlink} #{win_target}" }

  let(:verify_acl_command) { "icacls #{target_symlink}" }
  let(:acl_regex) { %r{.*\\bob:\(F\)} }

  let(:acl_manifest) do
    <<-MANIFEST
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

      file { '#{target_symlink}':
        ensure => link,
        target => '#{target}',
        require => User['#{user_id}'],
      }

      acl { "#{target_symlink}":
        permissions  => [
          { identity => '#{user_id}', rights => ['full'] },
        ],
        require      => File['#{target_symlink}']
      }
    MANIFEST
  end

  it 'applies manifest' do
    # not idempotent. complains that "Puppet cannot manage ACLs of symbolic links". This is a known constraint of the module, see: https://github.com/puppetlabs/puppetlabs-acl#Limitations
    apply_manifest(acl_manifest, catch_failures: true)
  end

  it 'verifies ACL rights' do
    run_shell(verify_acl_command) do |result|
      expect(result.stdout).not_to match(acl_regex)
    end
  end

  it 'verifies file data integrity' do
    expect(file(verify_content_path)).to be_file
    expect(file(verify_content_path).content).to match(%r{#{file_content}})
  end
end
