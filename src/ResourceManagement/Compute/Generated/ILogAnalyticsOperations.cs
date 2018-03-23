// <auto-generated>
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for
// license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// </auto-generated>

namespace Microsoft.Azure.Management.Compute.Fluent
{
    using Microsoft.Rest;
    using Microsoft.Rest.Azure;
    using Models;
    using System.Collections;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// LogAnalyticsOperations operations.
    /// </summary>
    public partial interface ILogAnalyticsOperations
    {
        /// <summary>
        /// Export logs that show Api requests made by this subscription in the
        /// given time window to show throttling activities.
        /// </summary>
        /// <param name='parameters'>
        /// Parameters supplied to the LogAnalytics getRequestRateByInterval
        /// Api.
        /// </param>
        /// <param name='location'>
        /// The location upon which virtual-machine-sizes is queried.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="Microsoft.Rest.Azure.CloudException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<AzureOperationResponse<LogAnalyticsOperationResultInner>> ExportRequestRateByIntervalWithHttpMessagesAsync(RequestRateByIntervalInputInner parameters, string location, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Export logs that show total throttled Api requests for this
        /// subscription in the given time window.
        /// </summary>
        /// <param name='parameters'>
        /// Parameters supplied to the LogAnalytics getThrottledRequests Api.
        /// </param>
        /// <param name='location'>
        /// The location upon which virtual-machine-sizes is queried.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="Microsoft.Rest.Azure.CloudException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<AzureOperationResponse<LogAnalyticsOperationResultInner>> ExportThrottledRequestsWithHttpMessagesAsync(ThrottledRequestsInputInner parameters, string location, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Export logs that show Api requests made by this subscription in the
        /// given time window to show throttling activities.
        /// </summary>
        /// <param name='parameters'>
        /// Parameters supplied to the LogAnalytics getRequestRateByInterval
        /// Api.
        /// </param>
        /// <param name='location'>
        /// The location upon which virtual-machine-sizes is queried.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="Microsoft.Rest.Azure.CloudException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<AzureOperationResponse<LogAnalyticsOperationResultInner>> BeginExportRequestRateByIntervalWithHttpMessagesAsync(RequestRateByIntervalInputInner parameters, string location, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
        /// <summary>
        /// Export logs that show total throttled Api requests for this
        /// subscription in the given time window.
        /// </summary>
        /// <param name='parameters'>
        /// Parameters supplied to the LogAnalytics getThrottledRequests Api.
        /// </param>
        /// <param name='location'>
        /// The location upon which virtual-machine-sizes is queried.
        /// </param>
        /// <param name='customHeaders'>
        /// The headers that will be added to request.
        /// </param>
        /// <param name='cancellationToken'>
        /// The cancellation token.
        /// </param>
        /// <exception cref="Microsoft.Rest.Azure.CloudException">
        /// Thrown when the operation returned an invalid status code
        /// </exception>
        /// <exception cref="Microsoft.Rest.SerializationException">
        /// Thrown when unable to deserialize the response
        /// </exception>
        /// <exception cref="Microsoft.Rest.ValidationException">
        /// Thrown when a required parameter is null
        /// </exception>
        Task<AzureOperationResponse<LogAnalyticsOperationResultInner>> BeginExportThrottledRequestsWithHttpMessagesAsync(ThrottledRequestsInputInner parameters, string location, Dictionary<string, List<string>> customHeaders = null, CancellationToken cancellationToken = default(CancellationToken));
    }
}
