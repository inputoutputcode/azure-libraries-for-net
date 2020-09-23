using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Definition;


namespace Microsoft.Azure.Management.ServiceFabric.Fluent
{
    internal partial class ServiceFabricClusterImpl
    {
        ServiceFabricCluster.Definition.IWithReliability ServiceFabricCluster.Definition.IWithWindowsImage.WithWindowsImage()
        {
            return this.WindowsImage();
        }
    }
}
