#! /usr/bin/env ruby
require 'spec_helper'
require 'puppet/type'
require 'puppet/type/acl'

describe Puppet::Type.type(:acl) do
  let(:resource) { Puppet::Type.type(:acl).new(:name => "acl") }
  let(:provider) { Puppet::Provider.new(resource) }

  before :each do
    resource.provider = provider
  end

  it "should be an instance of Puppet::Type::Acl" do
    resource.must be_an_instance_of Puppet::Type::Acl
  end

  context "parameter :name" do
    it "should be the name var" do
      resource.parameters[:name].isnamevar?.should be_true
    end

    it "should not allow nil" do
      expect {
        resource[:name] = nil
      }.to raise_error(Puppet::Error, /Got nil value for name/)
    end

    it "should not allow empty" do
      expect {
        resource[:name] = ''
      }.to raise_error(Puppet::ResourceError, /A non-empty name must/)
    end

    it "should accept any string value" do
      resource[:name] = 'value'
      resource[:name] = "c:/thisstring-location/value/somefile.txt"
      resource[:name] = "c:\\thisstring-location\\value\\somefile.txt"
    end
  end

  context "parameter :target" do
    it "should default to name" do
      resource[:target].must == resource[:name]
    end

    it "should not allow nil" do
      expect {
        resource[:target] = nil
      }.to raise_error(Puppet::Error, /Got nil value for target/)
    end

    it "should not allow empty" do
      expect {
        resource[:target] = ''
      }.to raise_error(Puppet::ResourceError, /A non-empty target must/)
    end

    it "should accept any string value" do
      resource[:target] = 'value'
      resource[:target] = "c:/thisstring-location/value/somefile.txt"
      resource[:target] = "c:\\thisstring-location\\value\\somefile.txt"
    end

    it "should not override :name" do
      resource[:target] = 'somevalue'
      resource[:target].should_not == resource[:name]
    end
  end

  context "parameter :target_type" do
    it "should default to :file" do
      resource[:target_type].must == :file
    end

    it "should accept :file" do
      resource[:target_type] = :file
    end

    it "should reject any other value" do
      expect {
        resource[:target_type] = :whenever
      }.to raise_error(Puppet::ResourceError, /Invalid value :whenever. Valid values are file/)
    end
  end

  context "parameter :purge" do
    it "should default to nil" do
      resource[:purge].must be_nil
    end

    it "should accept true" do
      resource[:purge] = true
    end

    it "should accept false" do
      resource[:purge] = false
    end

    it "should reject non-boolean values" do
      expect {
        resource[:purge] = :whenever
      }.to raise_error(Puppet::ResourceError, /Invalid value :whenever. Valid values are true/)
    end
  end

  context "property :owner" do
    it "should default to S-1-5-32-544 (Administrators)" do
      resource[:owner].must == 'S-1-5-32-544'
    end

    it "should accept bob" do
      resource[:owner] = 'bob'
    end

    it "should accept Domain\\Bob" do
      resource[:owner] = 'Domain\Bob'
    end

    it "should accept SIDs like S-1-5-32-544" do
      resource[:owner] = 'S-1-5-32-544'
    end

    it "should not allow nil" do
      expect {
        resource[:owner] = nil
      }.to raise_error(Puppet::Error, /Got nil value for owner/)
    end

    it "should not allow empty" do
      expect {
        resource[:owner] = ''
      }.to raise_error(Puppet::ResourceError, /A non-empty owner must/)
    end

    it "should accept any string value" do
      resource[:owner] = 'value'
      resource[:owner] = "c:/thisstring-location/value/somefile.txt"
      resource[:owner] = "c:\\thisstring-location\\value\\somefile.txt"
    end
  end

  context "property :inherit_parent_permissions" do
    it "should default to true" do
      resource[:inherit_parent_permissions].must == :true
    end

    it "should accept true" do
      resource[:inherit_parent_permissions] = true
    end

    it "should accept false" do
      resource[:inherit_parent_permissions] = false
    end

    it "should reject non-boolean values" do
      expect {
        resource[:inherit_parent_permissions] = :whenever
      }.to raise_error(Puppet::ResourceError, /Invalid value :whenever. Valid values are true/)
    end
  end

  context "property :permissions" do

    it "should not accept empty array" do
      expect {
        Puppet::Type.type(:acl).new(:name => "acl",:permissions =>[])
      }.to raise_error(Puppet::ResourceError, /Value for permissions should be an array with at least one element specified/)
    end

    it "should not allow empty string" do
      expect {
        resource[:permissions] = ''
      }.to raise_error(Puppet::ResourceError, /A non-empty permissions must be/)
    end

    it "should not allow nil" do
      expect {
        resource[:permissions] = nil
      }.to raise_error(Puppet::Error, /Got nil value for permissions/)
    end

    it "should be of type Array" do
      resource[:permissions] = [{'identity'=>'bob','rights'=>['full']}]
      resource[:permissions].must be_an_instance_of Array
    end

    it "should be an array that has elements of type Puppet::Type::Acl::Ace" do
      resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
      resource[:permissions].each do |permission|
        permission.must be_an_instance_of Puppet::Type::Acl::Ace
      end
    end

    context ":identity" do
      it "should accept bob" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
      end

      it "should accept Domain\\Bob" do
        resource[:permissions] = {'identity' =>'Domain\Bob','rights'=>['full']}
      end

      it "should accept SIDs like S-1-5-32-544" do
        resource[:permissions] = {'identity' =>'S-1-5-32-544','rights'=>['full']}
      end

      it "should reject empty" do
        expect {
          resource[:permissions] = {'rights'=>['full']}
        }.to raise_error(Puppet::ResourceError, /A non-empty identity must/)
      end

      it "should reject nil" do
        expect {
          resource[:permissions] = {'identity'=>nil,'rights'=>['full']}
        }.to raise_error(Puppet::ResourceError, /A non-empty identity must/)
      end
    end

    context ":rights" do
      it "should accept ['full']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['full']}
      end

      it "should accept ['modify']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['modify']}
      end

      it "should accept ['write']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['write']}
      end

      it "should accept ['list']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['list']}
      end

      it "should accept ['read']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['read']}
      end

      it "should accept ['execute']" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['execute']}
      end

      it "should accept a combination of valid values" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['read','execute']}
      end

      it "should reject any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['what']}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end

      it "should reject a value even if with valid values" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['modify','what']}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end

      it "should reject non-array value" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>'read'}
        }.to raise_error(Puppet::ResourceError, /Value for rights should be an array. Perhaps try \['read'\]\?/)
      end

      it "should reject empty" do
        expect {
          resource[:permissions] = {'identity'=>'bob'}
        }.to raise_error(Puppet::ResourceError, /A non-empty rights must/)
      end

      it "should reject nil" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>nil}
        }.to raise_error(Puppet::ResourceError, /A non-empty rights must/)
      end

      it "should reject emtpy array" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>[]}
        }.to raise_error(Puppet::ResourceError, /Value for rights should have least one element in the array/)
      end
    end

    context ":type" do
      it "should default to allow" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].type.should == 'allow'
      end

      it "should accept allow" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'allow'}
      end

      it "should accept deny" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'deny'}
      end

      it "should reject any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end

      it "should reject empty" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'type'=>''}
        }.to raise_error(Puppet::ResourceError, /Invalid value "". Valid values are/)
      end

      it "should set default value on nil" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'type'=>nil}
        resource[:permissions][0].type.should == 'allow'
      end
    end

    context ":child_types" do
      it "should default to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].child_types.should == 'all'
      end

      it "should accept all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'all'}
      end

      it "should accept objects" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'objects'}
      end

      it "should accept containers" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'containers'}
      end

      it "should reject any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end

      it "should reject empty" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'child_types'=>''}
        }.to raise_error(Puppet::ResourceError, /Invalid value "". Valid values are/)
      end

      it "should set default value on nil" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'child_types'=>nil}
        resource[:permissions][0].child_types.should == 'all'
      end
    end

    context ":affects" do
      it "should default to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].affects.should == 'all'
      end

      it "should accept all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'all'}
      end

      it "should accept self_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'self_only'}
      end

      it "should accept children_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'children_only'}
      end

      it "should accept self_and_direct_children" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'self_and_direct_children'}
      end

      it "should accept direct_children_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'direct_children_only'}
      end

      it "should reject any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end

      it "should reject empty" do
        expect {
          resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'affects'=>''}
        }.to raise_error(Puppet::ResourceError, /Invalid value "". Valid values are/)
      end

      it "should set default value on nil" do
        resource[:permissions] = {'identity'=>'bob','rights'=>['full'],'affects'=>nil}
        resource[:permissions][0].affects.should == 'all'
      end
    end

    context "when working with a single permission" do

      before :each do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
      end

      it "should convert the values appropriately" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}

        resource[:permissions][0].identity.should == 'bob'
        resource[:permissions][0].rights.should == ['full']
      end

      it "should set defaults" do
        resource[:permissions][0].type.should == 'allow'
        resource[:permissions][0].child_types.should == 'all'
        resource[:permissions][0].affects.should == 'all'
      end
    end

    context "when working with multiple permissions" do
      before :each do
        resource[:permissions] = [{'identity'=> 'bob','rights'=>['full']},{'identity'=> 'tim','rights'=>['full']}]
      end

      it "should contain the number of items set" do
        resource[:permissions].count.must == 2
      end

      it "should be in the exact order set" do
        resource[:permissions][0].identity.must == 'bob'
        resource[:permissions][1].identity.must == 'tim'
      end
    end

  end
end
