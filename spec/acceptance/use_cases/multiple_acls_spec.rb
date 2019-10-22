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

      user { "#{user_id1}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id2}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id3}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id4}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id5}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      user { "#{user_id6}":
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { "#{target}":
        permissions  => [
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['modify'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id3}', perm_type => 'allow', rights => ['write'] }
        ],
      }
      ->
      acl { "#{target_child}":
        permissions  => [
          { identity => '#{user_id4}', perm_type => 'deny', rights => ['full'] },
          { identity => '#{user_id5}', perm_type => 'allow', rights => ['modify'] },
          { identity => '#{user_id6}', perm_type => 'deny', rights => ['read'] }
        ],
      }
    MANIFEST
  end

  context 'ACL for Parent Path with Separate ACL for Child Path' do
    random_username = generate_random_username
    let(:test_short_name) { 'multi_acl' }
    let(:target_name) { "use_case_#{test_short_name}" }
    let(:target_child_name) { "use_case_child_#{test_short_name}" }

    let(:target) { "#{target_parent}/#{target_name}" }
    let(:target_child) { "#{target}/#{target_child_name}" }

    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }
    let(:user_id3) { 'billy' }
    let(:user_id4) { 'sarah' }
    let(:user_id5) { 'sally' }
    let(:user_id6) { 'betty' }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:verify_acl_child_command) { "icacls #{target_child}" }
    let(:user_id1_ace_regex) { %r{.*\\bob:(\(I\))?\(OI\)\(CI\)\(M\)} }
    let(:user_id2_ace_regex) { %r{.*\\#{user_id2}:(\(I\))?\(OI\)\(CI\)\(N\)} }
    let(:user_id3_ace_regex) { %r{.*\\billy:(\(I\))?\(OI\)\(CI\)\(W,Rc\)} }
    let(:user_id4_ace_regex) { %r{.*\\sarah:\(OI\)\(CI\)\(N\)} }
    let(:user_id5_ace_regex) { %r{.*\\sally:\(OI\)\(CI\)\(M\)} }
    let(:user_id6_ace_regex) { %r{.*\\betty:\(OI\)\(CI\)\(DENY\)\(R\)} }

    it 'applies manifest' do
      idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id2_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id3_ace_regex}})
        expect(result.stdout).not_to match(%r{#{user_id4_ace_regex}})
        expect(result.stdout).not_to match(%r{#{user_id5_ace_regex}})
        expect(result.stdout).not_to match(%r{#{user_id6_ace_regex}})
      end
    end

    it 'verifies child ACL rights' do
      run_shell(verify_acl_child_command) do |result|
        expect(result.stdout).to match(%r{#{user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id2_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id3_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id4_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id5_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id6_ace_regex}})
      end
    end
  end
end
