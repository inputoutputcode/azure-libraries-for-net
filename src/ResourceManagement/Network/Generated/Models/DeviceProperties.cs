// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Network.Fluent.Models
{
    using Newtonsoft.Json;
    using System.Linq;

    /// <summary>
    /// List of properties of the device.
    /// </summary>
    public partial class DeviceProperties
    {
        /// <summary>
        /// Initializes a new instance of the DeviceProperties class.
        /// </summary>
        public DeviceProperties()
        {
            CustomInit();
        }

        /// <summary>
        /// Initializes a new instance of the DeviceProperties class.
        /// </summary>
        /// <param name="deviceVendor">Name of the device Vendor.</param>
        /// <param name="deviceModel">Model of the device.</param>
        /// <param name="linkSpeedInMbps">Link speed.</param>
        public DeviceProperties(string deviceVendor = default(string), string deviceModel = default(string), int? linkSpeedInMbps = default(int?))
        {
            DeviceVendor = deviceVendor;
            DeviceModel = deviceModel;
            LinkSpeedInMbps = linkSpeedInMbps;
            CustomInit();
        }

        /// <summary>
        /// An initialization method that performs custom operations like setting defaults
        /// </summary>
        partial void CustomInit();

        /// <summary>
        /// Gets or sets name of the device Vendor.
        /// </summary>
        [JsonProperty(PropertyName = "deviceVendor")]
        public string DeviceVendor { get; set; }

        /// <summary>
        /// Gets or sets model of the device.
        /// </summary>
        [JsonProperty(PropertyName = "deviceModel")]
        public string DeviceModel { get; set; }

        /// <summary>
        /// Gets or sets link speed.
        /// </summary>
        [JsonProperty(PropertyName = "linkSpeedInMbps")]
        public int? LinkSpeedInMbps { get; set; }

    }
}