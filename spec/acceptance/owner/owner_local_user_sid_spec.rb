# frozen_string_literal: true

require 'spec_helper_acceptance'

sid = ''

describe 'Owner - SID' do
  let(:setup_manifest) do
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

  let(:acl_manifest) do
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
    let(:os_check_command) { 'cmd /c ver' }
    let(:os_check_regex) { %r{Version 5} }
    let(:file_content) { 'Rocket ship to the moon!' }
    let(:target_name) { 'owner_local_user_sid.txt' }
    let(:owner_id) { 'geraldo' }

    let(:get_owner_sid_command) do
      <<-CMD
        cmd /c "wmic useraccount where name='#{owner_id}' get sid"
      CMD
    end

    let(:sid_regex) { %r{^(S-.+)$} }

    let(:verify_content_path) { "#{target_parent}/#{target_name}" }
    let(:file_content_regex) { %r{\A#{file_content}\z} }

    let(:dosify_target) { "c:\\temp\\#{target_name}" }
    let(:verify_owner_command) { "cmd /c \"dir /q #{dosify_target}\"" }
    let(:owner_regex) { %r{.*\\#{owner_id}} }

    it 'applies setup manifest' do
      acl_idempotent_apply(setup_manifest)
    end

    it 'retrieves SID of user account' do
      run_shell(get_owner_sid_command) do |result|
        sid = sid_regex.match(result.stdout)[1]
      end
    end

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_owner_command) do |result|
        expect(result.stdout).to match(%r{#{owner_regex}})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
