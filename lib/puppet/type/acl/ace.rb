require 'puppet/parameter/value_collection'
require 'pathname'

class Puppet::Type::Acl
  class Ace
    require Pathname.new(__FILE__).dirname + '../../../' + 'puppet/type/acl/rights'

    attr_accessor :identity
    attr_accessor :sid
    attr_reader :rights
    attr_reader :type
    attr_reader :child_types
    attr_reader :affects
    attr_accessor :is_inherited
    attr_accessor :mask

    def initialize(permission_hash)
      @sid = permission_hash['sid']
      id = permission_hash['identity']
      @identity = validate_non_empty('identity', id.nil? || id.empty? ? @sid : id)
      self.rights = permission_hash['rights']
      self.type = permission_hash['type']
      self.child_types = permission_hash['child_types']
      self.affects = permission_hash['affects']
      @is_inherited = permission_hash['is_inherited'] || false
      @mask = permission_hash['mask']
    end

    def validate(value,*allowed_values)
      validator = Puppet::Parameter::ValueCollection.new
      validator.newvalues(*allowed_values)
      validator.validate(value)

      value
    end

    def is_inherited?
      return is_inherited
    end

    def convert_to_symbol(value)
      return nil if (value.nil? || value.empty?)
      return value if value.is_a?(Symbol)

      value.downcase.to_sym
    end

    def validate_non_empty(name,value)
      if value.nil? or value == ''
        raise ArgumentError, "A non-empty #{name} must be specified."
      end
      if value.kind_of?(Array) and value.count == 0
        raise ArgumentError, "Value for #{name} should have least one element in the array."
      end

      value
    end

    def validate_array(name,values)
      raise ArgumentError, "Value for #{name} should be an array. Perhaps try ['#{values}']?" unless values.kind_of?(Array)

      values
    end

    def validate_individual_values(values,*allowed_values)
      values.each do |value|
        validate(value,*allowed_values)
      end

      values
    end

    def convert_to_symbols(values)
      value_syms = []
      values.each do |value|
        value_syms << convert_to_symbol(value)
      end

      value_syms
    end

    def convert_from_symbols(symbols)
      values = []
      symbols.each do |value|
        values << value.to_s
      end

      values
    end

    def ensure_rights_order
      @rights.sort_by! { |r| Puppet::Type::Acl::Rights.new(r).order }
    end

    def ensure_rights_values_compatible
      if @rights.include?(:full) && rights.count != 1
        Puppet.warning("In each ace, when specifying rights, if you include 'full', it should be without anything else e.g. rights => ['full']. Please remove the extraneous rights from the manifest to remove this warning. Reference: #{to_s}")
        @rights = [:full]
      end
      if @rights.include?(:modify) && rights.count != 1
        Puppet.warning("In each ace, when specifying rights, if you include 'modify', it should be without anything else e.g. rights => ['modify']. Please remove the extraneous rights from the manifest to remove this warning. Reference: #{to_s}")
        @rights = [:modify]

      end
      if @rights.include?(:mask_specific) && rights.count != 1
        Puppet.warning("In each ace, when specifying rights, if you include 'mask_specific', it should be without anything else e.g. rights => ['mask_specific']. 'mask_specific' will be ignored unless it is by itself. Please remove the extraneous rights from the manifest to remove this warning. Reference: #{to_s}")
        @rights.delete_if { |r| r ==:mask_specific }
      end
    end

    def ensure_unique_values(values)
      if values.kind_of?(Array)
        return values.uniq
      end

      values
    end

    def ensure_none_or_self_only_sync
      return if @child_types.nil? ||@affects.nil?
      return if @child_types == :none && @affects == :self_only
      return unless @child_types == :none || @affects == :self_only

      if @child_types == :none && (@affects != :all && @affects != :self_only)
        Puppet.warning("If child_types => 'none', affects => value will be ignored. Please remove affects or set affects => 'self_only' to remove this warning. Reference: #{to_s}")
      end
      @affects = :self_only if @child_types == :none

      if @affects == :self_only && (@child_types != :all && @child_types != :none)
        Puppet.warning("If affects => 'self_only', child_types => value will be ignored. Please remove child_types or set child_types => 'none' to remove this warning. Reference: #{to_s}")
      end
      @child_types = :none if @affects == :self_only
    end

    def rights=(value)
      @rights = ensure_unique_values(
          convert_to_symbols(
          validate_individual_values(
          validate_array(
               'rights',
               validate_non_empty('rights', value)
          ),
          :full, :modify, :write, :list, :read, :execute, :mask_specific)))
      ensure_rights_order
      ensure_rights_values_compatible
    end

    def type=(value)
      @type = convert_to_symbol(validate(value || :allow, :allow, :deny))
    end

    def child_types=(value)
      @child_types = convert_to_symbol(validate(value || :all, :all, :objects, :containers, :none))
      ensure_none_or_self_only_sync
    end

    def affects=(value)
      @affects = convert_to_symbol(validate(value || :all, :all, :self_only, :children_only, :self_and_direct_children_only, :direct_children_only))
      ensure_none_or_self_only_sync
    end

    def to_s
      formatted_ace =""
      formatted_ace ="\n"
      formatted_ace << '{'
      formatted_ace << "identity => '#{identity}',"
      formatted_ace << " rights => #{rights},"
      formatted_ace << " type => '#{type}'," unless type == 'allow'
      formatted_ace << " child_types => '#{child_types}'," unless child_types == 'all'
      formatted_ace << " affects => '#{affects}'," unless affects == 'all'
      formatted_ace << " is_inherited => '#{is_inherited}'," if is_inherited
      formatted_ace << '}'

      formatted_ace
    end

  end
end
