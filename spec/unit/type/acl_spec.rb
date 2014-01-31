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
    context "when working with a single permission" do

      before :each do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
      end

      it "should be of type Array" do
        resource[:permissions].must be_an_instance_of Array
      end

      it "should have an array that has elements of type Puppet::Type::Acl::Ace" do
        resource[:permissions].each do |permission|
          permission.must be_an_instance_of Puppet::Type::Acl::Ace
        end
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

    context ":type" do
      it "should default to allow" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].type.should == 'allow'
      end

      it "should allow to be set to allow" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'allow'}
      end

      it "should allow to be set to deny" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'deny'}
      end

      it "should not allow to be set to any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'type'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end
    end

    context ":child_types" do
      it "should default to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].child_types.should == 'all'
      end

      it "should allow to be set to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'all'}
      end

      it "should allow to be set to objects" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'objects'}
      end

      it "should allow to be set to containers" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'containers'}
      end

      it "should not allow to be set to any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'child_types'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end
    end

    context ":affects" do
      it "should default to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full']}
        resource[:permissions][0].affects.should == 'all'
      end

      it "should allow to be set to all" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'all'}
      end

      it "should allow to be set to self_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'self_only'}
      end

      it "should allow to be set to children_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'children_only'}
      end

      it "should allow to be set to self_and_direct_children" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'self_and_direct_children'}
      end

      it "should allow to be set to direct_children_only" do
        resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'direct_children_only'}
      end

      it "should not allow to be set to any other value" do
        expect {
          resource[:permissions] = {'identity' =>'bob','rights'=>['full'],'affects'=>'what'}
        }.to raise_error(Puppet::ResourceError, /Invalid value "what". Valid values are/)
      end
    end


    it "should accept an array of hashes" do
      resource[:permissions] = ["{}","{}"]
    end

    pending "should not accept incomplete aces" do
      expect {
        resource[:permissions] = ''
      }.to raise_error(Puppet::ResourceError, /Invalid value for permissions/)
    end
  end
end
