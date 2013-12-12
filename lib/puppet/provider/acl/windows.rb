Puppet::Type.type(:acl).provide :windows do
  confine :operatingsystem => :windows
  defaultfor :operatingsystem => :windows

  has_features :ace_order_required

  def self.instances
    []
  end
end
