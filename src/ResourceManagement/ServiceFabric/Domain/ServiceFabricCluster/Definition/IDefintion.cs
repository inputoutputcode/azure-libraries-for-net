using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.Resource.Definition;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.GroupableResource.Definition;
using Microsoft.Azure.Management.Storage.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.ResourceActions;


namespace Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Definition
{
    /// <summary>
    /// ServiceFabric interface for all the definitions related to a ServiceFabric cluster.
    /// </summary>
    public interface IDefinition :
        IBlank,
        IWithGroup,
        IWithCreate
    { 
    }

    /// <summary>
    /// The stage of the definition which contains all the minimum required inputs for the resource to be created,
    /// but also allows for any other optional settings to be specified.
    /// </summary>
    public interface IWithCreate :
        ICreatable<IServiceFabricCluster>,
        IDefinitionWithTags<IWithCreate>
    {
    }

    /// <summary>
    /// The first stage of a container service definition.
    /// </summary>
    public interface IBlank :
        IDefinitionWithRegion<IWithGroup>
    {
    }

    public interface IWithGroup : IWithGroup<IWithVmImage>
    {
    }

    public interface IWithVmImage
    {
        IWithReliability WithVmImage(Environment environment);
    }

    public interface IWithReliability
    {
        IWithOneCertificateOnly WithReliability(ReliabilityLevel reliabilityLevel);
    }

    public interface IWithOneCertificateOnly
    {
        IWithStorageAccountDiagnostics WithOneCertificateOnly(X509Certificate2 x509Certificate2);
    }

    public interface IWithStorageAccountDiagnostics
    {
        IAddNodeType WithStorageAccountDiagnostics(IStorageAccount storageAccount);
    }
    
    public interface IAddNodeType
    {
        IWithCreate AddNodeType(string nodeTypeName);
    }
}
