require 'spec_helper_acceptance'

describe 'Directory - Deny Mask Specific' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/deny_#{mask}_rights_dir':
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { 'c:/temp/deny_#{mask}_rights_dir':
        permissions  => [
          { identity => '#{user_id}', perm_type => 'deny', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  let(:target) { "c:/temp/deny_#{mask}_rights_dir" }
  let(:verify_acl_command) { "icacls #{target}" }

  context '"AD, S, WA, X" Rights for Identity on Directory' do
    let(:mask) { '1048868' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(S,AD,X,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"DE, REA, WEA, RA, WA" Rights for Identity on Directory' do
    let(:mask) { '65944' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(D,REA,WEA,RA,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"RD, S, DC, WEA, RC" Rights for Identity on Directory' do
    let(:mask) { '131153' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(Rc,S,RD,WEA,DC\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"S, RA, WA, Rc" Rights for Identity on Directory' do
    let(:mask) { '1180032' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(Rc,S,RA,WA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end

  context '"WD, REA, RA, S" Rights for Identity on File' do
    let(:mask) { '1048714' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(DENY\)\(S,WD,REA,RA\)} }

    windows_agents.each do |agent|
      include_examples 'execute manifest', agent
    end
  end
end
