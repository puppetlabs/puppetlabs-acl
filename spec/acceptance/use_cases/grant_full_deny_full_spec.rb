require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
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
          { identity => '#{group}', perm_type => 'allow', rights => ['full'] },
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id}', perm_type => 'deny', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  let(:update_manifest) do
    <<-MANIFEST
      file { "#{target_child}":
        ensure  => file,
        content => 'Better Content'
      }
    MANIFEST
  end

  let(:acl_clear_manifest) do
    <<-MANIFEST
      acl { "#{target_child}":
        purge => true,
        permissions  => [
          { identity => '#{user_id}', perm_type => 'allow', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context "Inherit 'full' Rights for User's Group on Container and Deny User 'full' Rights on Object in Container" do
    let(:test_short_name) { 'grant_full_deny_full' }
    let(:file_content) { 'Sad people' }
    let(:target_name) { "use_case_#{test_short_name}" }
    let(:target_child_name) { "use_case_child_#{test_short_name}.txt" }
    let(:target) { "#{target_parent}/#{target_name}" }
    let(:target_child) { "#{target}/#{target_child_name}" }
    let(:verify_content_command) { "cat /cygdrive/c/temp/#{target_name}/#{target_child_name}" }
    let(:group) { 'Administrators' }
    let(:user_id) do
      # on AppVeyor the runtime user is not Administrator, requiring the username to be fetched
      run_shell(powershell('echo $env:UserName')).stdout.strip
    end
    let(:verify_acl_child_command) { "icacls #{target_child}" }
    let(:target_child_first_ace_regex) { %r{.*\\Administrators:\(I\)\(F\)} }
    let(:target_child_second_ace_regex) { %r{.*\\#{user_id}:\(N\)} }

    it 'applies manifest' do
      # not idempotent
      apply_manifest(acl_manifest)
    end

    it 'verifies ACL child rights' do
      run_shell(verify_acl_child_command) do |result|
        expect(result.stdout).to match(%r{#{target_child_first_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_second_ace_regex}})
      end
    end

    it 'attempts to update file, raises error' do
      apply_manifest(update_manifest, expect_failures: true) do |result|
        expect(result.stderr).to match(%r{Error:})
      end
    end

    it 'verifies file data integrity' do
      # acl needs to be cleared so Administrator has access to read contents
      apply_manifest(acl_clear_manifest)
      expect(file(target_child)).to be_file
      expect(file(target_child).content).to match(%r{#{file_content}})
    end
  end
end
