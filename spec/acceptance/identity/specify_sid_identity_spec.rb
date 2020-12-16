# frozen_string_literal: true

require 'spec_helper_acceptance'

sid = ''

describe 'Module - Identity' do
  let(:setup_manifest) do
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

  let(:acl_manifest) do
    <<-MANIFEST
      acl { '#{target_parent}/#{target_file}':
        permissions => [
          { identity => '#{sid}', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Specify SID Identity' do
    let(:os_check_command) { 'cmd /c ver' }
    let(:os_check_regex) { %r{Version 5} }
    let(:target_file) { 'specify_sid_ident.txt' }

    let(:file_content) { 'Magic unicorn rainbow madness!' }
    let(:verify_content_path) { "#{target_parent}/#{target_file}" }

    let(:get_user_sid_command) do
      <<-CMD
        cmd /c "wmic useraccount where name='#{user_id}' get sid"
      CMD
    end

    let(:sid_regex) { %r{^(S-.+)$} }
    let(:verify_acl_command) { "icacls #{target_parent}/#{target_file}" }
    let(:acl_regex) { %r{.*\\bob:\(F\)} }

    it 'applies setup manifest' do
      acl_idempotent_apply(setup_manifest)
    end

    it 'retrieves SID of user account' do
      run_shell(get_user_sid_command) do |result|
        sid = sid_regex.match(result.stdout)[1]
      end
    end

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{acl_regex}})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
