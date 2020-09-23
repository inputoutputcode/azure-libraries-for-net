// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using Fluent.Tests.Common;
using Microsoft.Azure.Management.KeyVault.Fluent;
using Microsoft.Azure.Management.ResourceManager.Fluent.Authentication;
using Microsoft.Azure.Management.ResourceManager.Fluent.Core;
using Microsoft.Azure.Management.KeyVault.Fluent.Models;
using System.Linq;
using Xunit;
using System;
using Microsoft.Rest.ClientRuntime.Azure.TestFramework;
using Azure.Tests;
using Microsoft.Azure.Test.HttpRecorder;
using Microsoft.Azure.Management.ResourceManager.Fluent;
using Microsoft.Azure.Management.Graph.RBAC.Fluent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;

namespace Fluent.Tests
{

    public class Secrets
    {

        /**
         * Main entry point.
         * @param args the parameters
         */
        [Fact]
        public void CanCRUDSecret()
        {
            using (var context = FluentMockContext.Start(GetType().FullName))
            {        
                IGraphRbacManager graphManager = TestHelper.CreateGraphRbacManager();
                string vaultName1 = TestUtilities.GenerateName("vault1");
                string secretName = TestUtilities.GenerateName("secret1");
                string rgName = TestUtilities.GenerateName("rgNEMV");

                IKeyVaultManager manager = TestHelper.CreateKeyVaultManager();

                var spnCredentialsClientId = HttpMockServer.Variables[ConnectionStringKeys.ServicePrincipalKey];

                try
                {
                    IVault vault = manager.Vaults
                            .Define(vaultName1)
                            .WithRegion(Region.USWest)
                            .WithNewResourceGroup(rgName)
                            .DefineAccessPolicy()
                                .ForServicePrincipal(spnCredentialsClientId)
                                .AllowKeyAllPermissions()
                                .AllowSecretAllPermissions()
                                .Attach()
                            .Create();
                    Assert.NotNull(vault);

                    SdkContext.DelayProvider.Delay(10000);

                    var secret = vault.Secrets.Define(secretName)
                            .WithValue("Some secret value")
                            .Create();

                    Assert.NotNull(secret);
                    Assert.NotNull(secret.Id);
                    Assert.Equal("Some secret value", secret.Value);

                    secret = secret.Update()
                            .WithValue("Some updated value")
                            .Apply();

                    Assert.Equal("Some updated value", secret.Value);

                    var versions = secret.ListVersions();

                    int count = 2;
                    foreach (var version in versions)
                    {
                        if ("Some secret value" == version.Value)
                        {
                            count--;
                        }
                        if ("Some updated value" == version.Value)
                        {
                            count--;
                        }
                    }
                    Assert.Equal(0, count);

                }
                finally
                {
                    try
                    {
                        TestHelper.CreateResourceManager().ResourceGroups.DeleteByName(rgName);
                    }
                    catch { }
                }
            }
        }

        [Fact]
        public void CanUploadPfxAsSecret()
        {
            using (var context = FluentMockContext.Start(GetType().FullName))
            {
                IGraphRbacManager graphManager = TestHelper.CreateGraphRbacManager();
                string vaultName1 = TestUtilities.GenerateName("vault1");
                string secretName = TestUtilities.GenerateName("secret1");
                string rgName = TestUtilities.GenerateName("rgNEMV");

                IKeyVaultManager manager = TestHelper.CreateKeyVaultManager();

                var spnCredentialsClientId = HttpMockServer.Variables[ConnectionStringKeys.ServicePrincipalKey];

                try
                {
                    IVault vault = manager.Vaults
                            .Define(vaultName1)
                            .WithRegion(Region.USWest)
                            .WithNewResourceGroup(rgName)
                            .DefineAccessPolicy()
                                .ForServicePrincipal(spnCredentialsClientId)
                                .AllowKeyAllPermissions()
                                .AllowSecretAllPermissions()
                                .Attach()
                            .Create();
                    Assert.NotNull(vault);

                    SdkContext.DelayProvider.Delay(10000);

                    string commonName = "mysfcluster.azure.com";
                    var certificate = CreateSelfSignedServerCertificate(commonName);
                    string rawCertData = Convert.ToBase64String(certificate.RawData, 0, certificate.RawData.Length);

                    var secret = vault.Secrets.Define("mysfcluster")
                            .WithValue(rawCertData)
                            .Create();

                    Assert.NotNull(secret);
                    Assert.NotNull(secret.Id);
                    Assert.Equal("Some secret value", secret.Value);
                }
                finally
                {
                    try
                    {
                        TestHelper.CreateResourceManager().ResourceGroups.DeleteByName(rgName);
                    }
                    catch { }
                }
            }
        }

        private X509Certificate2 CreateSelfSignedServerCertificate(string commonName)
        {
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddDnsName(commonName);

            var distinguishedName = new X500DistinguishedName($"CN={commonName}");

            using (var rsa = RSA.Create(2048))
            {
                var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, false));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2"), new Oid("1.3.6.1.5.5.7.3.1") }, false));
                request.CertificateExtensions.Add(sanBuilder.Build());

                var certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));
                certificate.FriendlyName = commonName;

                return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "Corp123!Corp1232!"), "Corp123!Corp1232!", X509KeyStorageFlags.MachineKeySet);
            }
        }
    }
}