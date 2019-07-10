require 'spec_helper_acceptance'

describe 'File - Deny Mask Specific' do
  let(:acl_manifest) do
    <<-MANIFEST
      file { '#{target_parent}':
        ensure => directory
      }

      file { 'c:/temp/deny_#{mask}_rights_file.txt':
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

      acl { 'c:/temp/deny_#{mask}_rights_file.txt':
        permissions  => [
          { identity => '#{user_id}', perm_type => 'deny', rights => ['mask_specific'], mask => '#{mask}' },
        ],
      }
    MANIFEST
  end

  let(:verify_acl_command) { "icacls c:/temp/deny_#{mask}_rights_file.txt" }

  let(:verify_content_path) { "c:\\temp\\deny_#{mask}_rights_file.txt" }

  context '"AD, S, WA, X" Rights for Identity on File' do
    let(:mask) { '1048868' }
    let(:file_content) { 'Slippery when dry.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(S,AD,X,WA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"RD, DE, WEA, RC" Rights for Identity on File' do
    let(:mask) { '196625' }
    let(:file_content) { 'Pressure, oh the pressure.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(D,Rc,RD,WEA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"S, DE, REA, WEA, RA, WA" Rights for Identity on File' do
    let(:mask) { '1114520' }
    let(:file_content) { 'Gallons of hats on your head.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(D,REA,WEA,RA,WA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"S, RA, WA, RC" Rights for Identity on File' do
    let(:mask) { '1180032' }
    let(:file_content) { 'We need experienced fighter pilots to train these pigs in the basics of aviation!' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(Rc,S,RA,WA\)} }

    include_examples 'execute manifest and verify file'
  end

  context '"WD, REA, RA, S" Rights for Identity on File' do
    let(:mask) { '1048714' }
    let(:file_content) { 'Tiny little people with small problems.' }
    let(:acl_regex) { %r{.*\\bob:\(DENY\)\(S,WD,REA,RA\)} }

    include_examples 'execute manifest and verify file'
  end
end
