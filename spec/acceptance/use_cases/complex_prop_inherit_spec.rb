require 'spec_helper_acceptance'

# TODO: FIX TESTS

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }
      group { "#{group1}":
        ensure => present
      }
      group { "#{group2}":
        ensure => present
      }
      user { "#{user_id1}":
        ensure     => present,
        groups     => ['Users', '#{group1}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group1}']
      }
      user { "#{user_id2}":
        ensure     => present,
        groups     => ['Users', '#{group2}'],
        managehome => true,
        password   => "L0v3Pupp3t!",
        require => Group['#{group2}']
      }
      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }
      ->
      acl { "#{target}":
        purge           => 'true',
        permissions     => [
          {
            identity    => 'Administrators',
            perm_type => 'allow',
            rights => ['full']
          },
          { identity    => '#{user_id1}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'all'
          },
          { identity    => '#{user_id2}',
            perm_type   => 'deny',
            rights      => ['read','execute'],
            affects     => 'children_only',
            child_types => 'objects'
          },
          { identity    => '#{group1}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'containers'
          },
          { identity    => '#{group2}',
            perm_type   => 'allow',
            rights      => ['read'],
            affects     => 'children_only',
            child_types => 'all'
          }
        ],
        inherit_parent_permissions => 'false'
      }
      ->
      file { "#{target_child}":
        ensure  => directory
      }
      ->
      acl { "#{target_child}":
        purge           => 'true',
        permissions     => [
          { identity    => '#{user_id1}',
            perm_type   => 'deny',
            rights      => ['modify'],
            affects     => 'children_only',
            child_types => 'objects'
          },
          { identity    => '#{user_id2}',
            perm_type   => 'allow',
            rights      => ['full'],
            affects     => 'children_only',
            child_types => 'containers'
          }
        ],
      }
      ->
      file { "#{target_grand_child}":
        ensure  => file,
        content => '#{file_content}'
      }
      ->
      acl { "#{target_grand_child}":
        permissions  => [
          { identity    => '#{group2}',
            perm_type   => 'deny',
            rights      => ['full'],
            affects     => 'self_only'
          }
        ],
      }
    MANIFEST
  end

  context 'Complex Propagation and Inheritance with Nested Paths' do
    random_username = generate_random_username
    let(:test_short_name) { 'complex_prop_inherit' }
    let(:file_content) { 'Sight seeing blind people.' }

    let(:target_name) { "use_case_#{test_short_name}" }
    let(:target_child_name) { "use_case_child_#{test_short_name}" }
    let(:target_grand_child_name) { "use_case_grand_child_#{test_short_name}.txt" }

    let(:target) { "#{target_parent}/#{target_name}" }
    let(:target_child) { "#{target}/#{target_child_name}" }
    let(:target_grand_child) { "#{target_child}/#{target_grand_child_name}" }

    let(:verify_content_path) { "#{target_parent}/#{target_name}/#{target_child_name}/#{target_grand_child_name}" }

    let(:group1) { 'jerks' }
    let(:group2) { 'cool_peeps' }

    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:verify_acl_grand_child_command) { "icacls #{target_grand_child}" }

    let(:target_grand_child_first_ace_regex) { %r{.*\\cool_peeps:\(N\)} }
    let(:target_grand_child_second_ace_regex) { %r{.*\\bob:\(I\)\(DENY\)\(M\)} }
    let(:target_grand_child_third_ace_regex) { %r{.*\\Administrators:\(I\)\(F\)} }
    let(:target_grand_child_fourth_ace_regex) { %r{.*\\bob:\(I\)\(R\)} }
    let(:target_grand_child_fifth_ace_regex) { %r{.*\\#{user_id2}:\(I\)\(DENY\)\(RX\)} }
    let(:target_grand_child_sixth_ace_regex) { %r{.*\\cool_peeps:\(I\)\(R\)} }

    it 'applies manifest' do
      acl_idempotent_apply(acl_manifest)
    end

    it 'verifies ACL grand child rights' do
      run_shell(verify_acl_grand_child_command) do |result|
        # We only need to check the grand child because we are only concerned with rights
        # propagating and inheriting.
        expect(result.stdout).to match(%r{#{target_grand_child_first_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_second_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_third_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_fourth_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_fifth_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_sixth_ace_regex}})
      end
    end

    it 'verfies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
