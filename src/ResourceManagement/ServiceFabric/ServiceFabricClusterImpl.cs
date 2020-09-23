using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.Management.ServiceFabric.Fluent.Models;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Update;
using Microsoft.Azure.Management.ServiceFabric.Fluent.ServiceFabricCluster.Definition;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.ResourceActions;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core.Resource.Definition;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;

using Environment = Microsoft.Azure.Management.ServiceFabric.Fluent.Models.Environment;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Azure.Management.Storage.Fluent;
using System.IO;
using Microsoft.Azure.Management.Compute.Fluent.Models;

namespace Microsoft.Azure.Management.ServiceFabric.Fluent
{
    /// <summary>
    /// The implementation for ServiceFabricCluster and its create and update interfaces.
    /// </summary>
    internal partial class ServiceFabricClusterImpl :
        GroupableResource<
            IServiceFabricCluster,
            ClusterParameters,
            ServiceFabricClusterImpl,
            IServiceFabricManager,
            IWithGroup,
            IWithWindowsImage,
            IWithCreate,
            IUpdate>,
        IServiceFabricCluster,
        IDefinition,
        IUpdate
    {
        string IIndexable.Key => throw new NotImplementedException();

        public string ClusterState => throw new NotImplementedException();

        internal ServiceFabricClusterImpl(string name, ClusterParameters innerModel, IServiceFabricManager manager)
            : base(name, innerModel, manager)
        {
            this.InitializeChildrenFromInner();
        }

        public ServiceFabricClusterImpl WindowsImage()
        {
            this.Inner.VmImage = Environment.Windows.ToString();

            return this;
        }

        public ServiceFabricClusterImpl ReliabilityLevel(ReliabilityLevel reliabilityLevel)
        {
            this.Inner.ReliabilityLevel = reliabilityLevel;

            return this;
        }

        public IWithStorageAccountDiagnostics WithOneCertificateOnly(X509Certificate2 x509Certificate2)
        {
            this.Inner.Certificate.Thumbprint = x509Certificate2.Thumbprint;
            this.Inner.Certificate.X509StoreName = X509StoreName.My;

            return this;
        }

        public IAddNodeType WithStorageAccountDiagnostics(IStorageAccount storageAccount)
        {
            this.Inner.DiagnosticsStorageAccountConfig.StorageAccountName = storageAccount.Name;
            this.Inner.DiagnosticsStorageAccountConfig.ProtectedAccountKeyName = "StorageAccountKey1";
            this.Inner.DiagnosticsStorageAccountConfig.QueueEndpoint = storageAccount.EndPoints.Primary.Queue;
            this.Inner.DiagnosticsStorageAccountConfig.TableEndpoint = storageAccount.EndPoints.Primary.Table;
            this.Inner.DiagnosticsStorageAccountConfig.BlobEndpoint = storageAccount.EndPoints.Primary.Blob;

            return this;
        }

        public IWithDefaults AddNodeType(string nodeTypeName)
        {
            var nodeTypeDescription = new NodeTypeDescription()
            {
                Name = nodeTypeName,
                ApplicationPorts = new EndpointRangeDescription(20000, 30000),
                ClientConnectionEndpointPort = 19000,
                DurabilityLevel = DurabilityLevel.Silver,
                EphemeralPorts = new EndpointRangeDescription(49152, 65534),
                HttpGatewayEndpointPort = 19080,
                IsPrimary = true,
                VmInstanceCount = 5
            };

            this.Inner.NodeTypes.Add(nodeTypeDescription);

            return this;
        }

        protected void InitializeChildrenFromInner()
        {
            this.Inner.Certificate = new CertificateDescription();
            this.Inner.DiagnosticsStorageAccountConfig = new DiagnosticsStorageAccountConfig();
            this.Inner.NodeTypes = new List<NodeTypeDescription>();
            this.Inner.FabricSettings = new List<SettingsSectionDescription>();
            this.Inner.AddOnFeatures = new List<AddOnFeatures>();
            this.Inner.ClientCertificateCommonNames = new List<ClientCertificateCommonName>();
            this.Inner.ClientCertificateThumbprints = new List<ClientCertificateThumbprint>();
            this.Inner.UpgradeDescription = new ClusterUpgradePolicy()
            {
                ForceRestart = false,
                UpgradeReplicaSetCheckTimeout = "10675199.02:48:05.4775807",
                HealthCheckWaitDuration = "00:05:00",
                HealthCheckStableDuration = "00:05:00",
                HealthCheckRetryTimeout = "00:45:00",
                UpgradeTimeout = "12:00:00",
                UpgradeDomainTimeout = "02:00:00",
                HealthPolicy = new ClusterHealthPolicy()
                {
                    MaxPercentUnhealthyNodes = 20,
                    MaxPercentUnhealthyApplications = 20
                },
                DeltaHealthPolicy = new ClusterUpgradeDeltaHealthPolicy()
                {
                    MaxPercentDeltaUnhealthyNodes = 0,
                    MaxPercentUpgradeDomainDeltaUnhealthyNodes = 0,
                    MaxPercentDeltaUnhealthyApplications = 0
                }
            };
        }

        public IWithCreate WithDefaults()
        {
            //this.Inner.ClusterCodeVersion = "7.1.409.9590";
            var fabricSettings = new SettingsSectionDescription();
            fabricSettings.Name = "Security";
            fabricSettings.Parameters = new List<SettingsParameterDescription>() { new SettingsParameterDescription("ClusterProtectionLevel", "EncryptAndSign") };
            this.Inner.FabricSettings.Add(fabricSettings);
            this.Inner.ManagementEndpoint = $"https://{this.Name}.{this.Region.Name}.cloudapp.azure.com:19000";
            this.Inner.UpgradeMode = Models.UpgradeMode.Automatic;

            return this;
        }

        public async override Task<IServiceFabricCluster> CreateResourceAsync(CancellationToken cancellationToken)
        {
            ServiceFabricClusterImpl self = this;
            if (IsInCreateMode)
            {
                var inner = await this.Manager.Inner.Clusters.CreateOrUpdateAsync(this.ResourceGroupName, this.Name, this.Inner, cancellationToken);
                SetInner(inner);

                return this;
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        protected override Task<ClusterParameters> GetInnerAsync(CancellationToken cancellationToken)
        {
            throw new NotImplementedException();
        }

        ServiceFabricVersion IServiceFabricCluster.Version => throw new NotImplementedException();

        IServiceFabricManager IHasManager<IServiceFabricManager>.Manager => throw new NotImplementedException();

    }
}

