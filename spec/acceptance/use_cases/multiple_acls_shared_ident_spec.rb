require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => directory,
        require => File['#{target_parent}']
      }

      file { "#{target_child}":
        ensure  => directory,
        require => File['#{target}']
      }

      file { "#{target_grand_child}":
        ensure  => directory,
        require => File['#{target_child}']
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

      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['read','execute'] },
          { identity => '#{group1}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{group2}', perm_type => 'allow', rights => ['read'] }
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['write'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['write'] },
          { identity => '#{group1}', perm_type => 'allow', rights => ['execute'] },
          { identity => '#{group2}', perm_type => 'allow', rights => ['execute'] }
        ],
      }
      ->
      acl { "#{target_grand_child}":
        permissions  => [
          { identity => '#{user_id1}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{group1}', perm_type => 'allow', rights => ['full'] },
          { identity => '#{group2}', perm_type => 'allow', rights => ['full'] },
        ],
      }
    MANIFEST
  end

  context 'Multiple ACL for Nested Paths with Varying Rights for Same Identity' do
    random_username = generate_random_username
    let(:test_short_name) { 'multi_acl_shared_ident' }
    let(:target_name) { "use_case_#{test_short_name}" }
    let(:target_child_name) { "use_case_child_#{test_short_name}" }
    let(:target_grand_child_name) { "use_case_grand_child_#{test_short_name}" }
    let(:target) { "#{target_parent}/#{target_name}" }
    let(:target_child) { "#{target}/#{target_child_name}" }
    let(:target_grand_child) { "#{target_child}/#{target_grand_child_name}" }

    let(:group1) { 'jerks' }
    let(:group2) { 'cool_peeps' }

    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:verify_acl_child_command) { "icacls #{target_child}" }
    let(:verify_acl_grand_child_command) { "icacls #{target_grand_child}" }

    let(:target_group1_ace_regex) { %r{.*\\jerks:(\(I\))?\(OI\)\(CI\)\(R\)} }
    let(:target_group2_ace_regex) { %r{.*\\cool_peeps:(\(I\))?\(OI\)\(CI\)\(R\)} }
    let(:target_user_id1_ace_regex) { %r{.*\\bob:(\(I\))?\(OI\)\(CI\)\(R\)} }
    let(:target_user_id2_ace_regex) { %r{.*\\#{user_id2}:(\(I\))?\(OI\)\(CI\)\(DENY\)\(RX\)} }

    let(:target_child_group1_ace_regex) { %r{.*\\jerks:(\(I\))?\(OI\)\(CI\)\(Rc,S,X,RA\)} }
    let(:target_child_group2_ace_regex) { %r{.*\\cool_peeps:(\(I\))?\(OI\)\(CI\)\(Rc,S,X,RA\)} }
    let(:target_child_user_id1_ace_regex) { %r{.*\\bob:(\(I\))?\(OI\)\(CI\)\(W,Rc\)} }
    let(:target_child_user_id2_ace_regex) { %r{.*\\#{user_id2}:(\(I\))?\(OI\)\(CI\)\(DENY\)\(W,Rc\)} }

    let(:target_grand_child_group1_ace_regex) { %r{.*\\jerks:\(OI\)\(CI\)\(F\)} }
    let(:target_grand_child_group2_ace_regex) { %r{.*\\cool_peeps:\(OI\)\(CI\)\(F\)} }
    let(:target_grand_child_user_id1_ace_regex) { %r{.*\\bob:\(OI\)\(CI\)\(N\)} }
    let(:target_grand_child_user_id2_ace_regex) { %r{.*\\#{user_id2}:\(OI\)\(CI\)\(N\)} }

    it 'applies manifest' do
      idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{target_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id2_ace_regex}})
      end
    end

    it 'verifies child ACL rights' do
      run_shell(verify_acl_child_command) do |result|
        # ACL from parent(s) will still apply.
        expect(result.stdout).to match(%r{#{target_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id2_ace_regex}})

        expect(result.stdout).to match(%r{#{target_child_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_user_id2_ace_regex}})
      end
    end

    it 'verifies grand child ACL rights' do
      run_shell(verify_acl_grand_child_command) do |result|
        # ACL from parent(s) will still apply.
        expect(result.stdout).to match(%r{#{target_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_user_id2_ace_regex}})

        # ACL from parent(s) will still apply.
        expect(result.stdout).to match(%r{#{target_child_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_child_user_id2_ace_regex}})

        expect(result.stdout).to match(%r{#{target_grand_child_group1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_group2_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{target_grand_child_user_id2_ace_regex}})
      end
    end
  end
end
