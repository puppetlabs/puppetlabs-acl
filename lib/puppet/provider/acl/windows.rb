Puppet::Type.type(:acl).provide :windows do
  confine :operatingsystem => :windows
  defaultfor :operatingsystem => :windows

  has_features :ace_order_required
  has_features :can_inherit_parent_permissions

  def self.instances
    []
  end
end
