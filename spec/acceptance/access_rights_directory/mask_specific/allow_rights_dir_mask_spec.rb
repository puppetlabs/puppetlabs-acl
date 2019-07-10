require 'spec_helper_acceptance'

describe 'Allow Mask Specific' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/allow_#{mask}_rights_dir':
        ensure  => directory,
        require => File['#{target_parent}']
      }

      user { '#{user_id}':
        ensure     => present,
        groups     => 'Users',
        managehome => true,
        password   => "L0v3Pupp3t!"
      }

      acl { 'c:/temp/allow_#{mask}_rights_dir':
        permissions  => [
          { identity => '#{user_id}', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  let(:target) { "c:/temp/allow_#{mask}_rights_dir" }
  let(:verify_acl_command) { "icacls #{target}" }

  context '"AD, S, WA, X" Rights for Identity on Directory' do
    let(:mask) { '1048868' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(S,AD,X,WA\)} }

    include_examples 'execute manifest'
  end

  context '"RD, DC, WEA, RC" Rights for Identity on Directory' do
    let(:mask) { '131153' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(Rc,RD,WEA,DC\)} }

    include_examples 'execute manifest'
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on Directory' do
    let(:mask) { '1114520' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(D,REA,WEA,RA,WA\)} }

    include_examples 'execute manifest'
  end

  context '"S, RA, WA, RC" Rights for Identity on Directory' do
    let(:mask) { '1180032' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(Rc,S,RA,WA\)} }

    include_examples 'execute manifest'
  end

  context '"WD, REA, RA, S" Rights for Identity on Directory' do
    let(:mask) { '1048714' }
    let(:acl_regex) { %r{.*\\bob:\(OI\)\(CI\)\(S,WD,REA,RA\)} }

    include_examples 'execute manifest'
  end
end
