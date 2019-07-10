require 'spec_helper_acceptance'

describe 'Use Cases' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { "#{target_parent}":
        ensure => directory
      }

      file { "#{target}":
        ensure  => file,
        content => '#{file_content}',
        require => File['#{target_parent}']
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
          { identity => '#{user_id1}', perm_type => 'allow', rights => ['full'] },
          { identity => '#{user_id2}', perm_type => 'deny', rights => ['modify'] },
          { identity => '#{user_id3}', perm_type => 'allow', rights => ['read'] },
          { identity => '#{user_id4}', perm_type => 'deny', rights => ['read','execute'] },
          { identity => '#{user_id5}', perm_type => 'allow', rights => ['write','execute'] },
          { identity => '#{user_id6}', perm_type => 'deny', rights => ['write','read'] }
        ],
      }
    MANIFEST
  end

  context 'Multiple ACEs for Target Path' do
    random_username = generate_random_username

    let(:test_short_name) { 'multi_aces' }
    let(:file_content) { 'Ninjas all up in my face!' }
    let(:target_name) { "use_case_#{test_short_name}.txt" }
    let(:target) { "#{target_parent}/#{target_name}" }

    let(:user_id1) { 'bob' }
    let(:user_id2) { random_username }
    let(:user_id3) { 'billy' }
    let(:user_id4) { 'sarah' }
    let(:user_id5) { 'sally' }
    let(:user_id6) { 'betty' }

    let(:verify_content_path) { "#{target_parent}/#{target_name}" }

    let(:verify_acl_command) { "icacls #{target}" }
    let(:user_id1_ace_regex) { %r{.*\\bob:\(F\)} }
    let(:user_id2_ace_regex) { %r{.*\\#{user_id2}:\(DENY\)\(M\)} }
    let(:user_id3_ace_regex) { %r{.*\\billy:\(R\)} }
    let(:user_id4_ace_regex) { %r{.*\\sarah:\(DENY\)\(RX\)} }
    let(:user_id5_ace_regex) { %r{.*\\sally:\(W,Rc,X,RA\)} }
    let(:user_id6_ace_regex) { %r{.*\\betty:\(DENY\)\(R,W\)} }

    it 'applies manifest' do
      idempotent_apply(acl_manifest)
    end

    it 'verifies ACL rights ' do
      run_shell(verify_acl_command) do |result|
        expect(result.stdout).to match(%r{#{user_id1_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id2_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id3_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id4_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id5_ace_regex}})
        expect(result.stdout).to match(%r{#{user_id6_ace_regex}})
      end
    end

    it 'verifies file data integrity' do
      expect(file(verify_content_path)).to be_file
      expect(file(verify_content_path).content).to match(%r{#{file_content}})
    end
  end
end
