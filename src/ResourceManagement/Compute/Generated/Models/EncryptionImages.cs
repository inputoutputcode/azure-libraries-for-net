// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Compute.Fluent.Models
{
    using Newtonsoft.Json;
    using System.Collections;
    using System.Collections.Generic;
    using System.Linq;

    /// <summary>
    /// Optional. Allows users to provide customer managed keys for encrypting
    /// the OS and data disks in the gallery artifact.
    /// </summary>
    public partial class EncryptionImages
    {
        /// <summary>
        /// Initializes a new instance of the EncryptionImages class.
        /// </summary>
        public EncryptionImages()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the EncryptionImages class.
        /// </summary>
        /// <param name="dataDiskImages">A list of encryption specifications
        /// for data disk images.</param>
        public EncryptionImages(OSDiskImageEncryption osDiskImage = default(OSDiskImageEncryption), IList<DataDiskImageEncryption> dataDiskImages = default(IList<DataDiskImageEncryption>))
        {
            OsDiskImage = osDiskImage;
            DataDiskImages = dataDiskImages;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// </summary>
        [JsonProperty(PropertyName = "osDiskImage")]
        public OSDiskImageEncryption OsDiskImage { get; set; }

        /// <summary>
        /// Gets or sets a list of encryption specifications for data disk
        /// images.
        /// </summary>
        [JsonProperty(PropertyName = "dataDiskImages")]
        public IList<DataDiskImageEncryption> DataDiskImages { get; set; }

    }
}
