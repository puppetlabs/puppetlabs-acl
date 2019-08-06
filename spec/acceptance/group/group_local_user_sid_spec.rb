require 'spec_helper_acceptance'

sid = ''

describe 'Group - SID' do
  context 'Change Group to Local User SID' do
    let(:setup_manifest) do
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

    let(:acl_manifest) do
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

    let(:user_type) { 'local_user_sid' }
    let(:file_content) { 'Hot eyes in your sand!' }

    let(:target_name) { "group_#{user_type}.txt" }

    let(:target) { "#{target_parent}/#{target_name}" }
    let(:user_id) { 'bob' }
    let(:group_id) { 'tom' }

    let(:get_group_sid_command) do
      <<-CMD
        cmd /c "wmic useraccount where name='#{group_id}' get sid"
      CMD
    end

    let(:sid_regex) { %r{^(S-.+)$} }

    let(:verify_content_path) { "#{target_parent}/#{target_name}" }

    let(:verify_group_command) { "icacls #{target}" }
    let(:group_regex) { %r{.*\\tom:\(M\)} }

    it 'applies setup manifest' do
      idempotent_apply(setup_manifest)
    end

    it 'retrieves SID of user account' do
      run_shell(get_group_sid_command) do |result|
        sid = sid_regex.match(result.stdout)[1]
      end
    end

    it 'applies ACL manifest' do
      # TODO: find out why this is not idempotent
      idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_group_command) do |result|
        expect(result.stdout).to match(%r{#{group_regex}})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
