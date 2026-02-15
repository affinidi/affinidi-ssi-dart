import '../../ssi.dart';

/// A URI-based representation of a Decentralized Identifier (DID).
///
/// [DidX] wraps a standard Dart [Uri] and provides specialized access to DID components.
/// Unlike the [Did] class which implements the Uri interface directly, this class
/// uses composition by wrapping a Uri object.
///
/// ## DID Syntax
///
/// DIDs follow the format: `did:{method}:{method-specific-id}`
///
/// Components:
/// - **scheme**: Always `"did"` - identifies this as a Decentralized Identifier
/// - **method**: The DID method name (e.g., `"web"`, `"key"`, `"webvh"`)
/// - **method-specific-id**: The unique identifier within the DID method's namespace
///
/// ## Features
///
/// - Validates DID format on parsing
/// - Provides convenient access to DID components
/// - Preserves the full URI for query parameters and fragments
/// - Supports equality comparison and hashing
///
/// ## Usage
///
/// ```dart
/// // Parse a DID string
/// final did = DidX.parse('did:example:123456789abcdefghi');
/// 
/// // Access components
/// print(did.scheme); // 'did'
/// print(did.method); // 'example'
/// print(did.methodSpecificId); // '123456789abcdefghi'
/// 
/// // Convert back to string
/// print(did.toString()); // 'did:example:123456789abcdefghi'
/// 
/// // DIDs with query parameters
/// final didWithQuery = DidX.parse('did:web:example.com?versionId=1');
/// print(didWithQuery.methodSpecificId); // 'example.com?versionId=1'
/// ```
///
/// See also:
/// - [Did] - A lightweight DID implementation that directly implements the Uri interface
/// - W3C DID Core Specification: https://www.w3.org/TR/did-core/
class DidX {
  /// The underlying URI representation of the DID.
  ///
  /// This private field stores the complete URI including scheme, path,
  /// query parameters, and fragments.
  final Uri _uri;

  /// Creates a [DidX] from a URI.
  ///
  /// This public constructor allows subclasses to extend [DidX] by providing
  /// their own URI. The URI should have the "did" scheme, though this constructor
  /// does not enforce validation.
  ///
  /// **Important**: For creating DIDs from strings, prefer using [DidX.parse]
  /// which validates the DID format.
  ///
  /// Parameters:
  /// - [_uri]: A URI with the "did" scheme
  ///
  /// Example:
  /// ```dart
  /// final uri = Uri.parse('did:web:example.com');
  /// final did = DidX(uri);
  /// ```
  DidX(this._uri);

  /// Creates a [DidX] from a URI (private constructor).
  ///
  /// This private constructor is used internally by factory methods.
  /// External code should use [DidX.parse] to create DID instances.
  ///
  /// Parameters:
  /// - [_uri]: A validated URI with the "did" scheme
  DidX._(this._uri);

  /// Parses a DID string and returns a [DidX] instance.
  ///
  /// This factory constructor validates the DID format and ensures:
  /// - The string is a valid URI
  /// - The scheme is exactly "did"
  /// - The path contains a method and method-specific identifier
  ///
  /// Parameters:
  /// - [did]: A string representation of a DID (e.g., `'did:web:example.com'`)
  ///
  /// Returns a validated [DidX] instance.
  ///
  /// Throws [FormatException] if:
  /// - The string is not a valid URI
  /// - The URI scheme is not "did"
  /// - The path is empty
  /// - The path doesn't contain both method and method-specific-id (missing `:` separator)
  ///
  /// Examples:
  /// ```dart
  /// // Simple DID
  /// final did = DidX.parse('did:web:example.com');
  /// 
  /// // DID with path components
  /// final didWithPath = DidX.parse('did:webvh:z6Mk:example.com:path');
  /// 
  /// // DID with query parameters
  /// final didWithQuery = DidX.parse('did:web:example.com?service=hub');
  /// ```
  factory DidX.parse(String did) {
    final uri = Uri.parse(did);
    if (uri.scheme != 'did') {
      throw FormatException('Invalid DID: scheme must be "did"', did);
    }
    if (uri.path.isEmpty) {
      throw FormatException('Invalid DID: path cannot be empty', did);
    }
    if (!uri.path.contains(':')) {
      throw FormatException(
          'Invalid DID: path must contain method and method-specific-id separated by ":"',
          did);
    }
    return DidX._(uri);
  }

  /// The URI scheme of the DID.
  ///
  /// For valid DIDs, this will always be `"did"`. This getter provides access
  /// to the scheme component of the underlying URI.
  ///
  /// Returns the string `"did"`.
  String get scheme => _uri.scheme;

  /// The path component of the DID URI.
  ///
  /// The path contains both the method and method-specific identifier.
  /// For example, in `did:web:example.com`, the path is `web:example.com`.
  ///
  /// This differs from standard HTTP URIs where paths start with `/`.
  /// DID paths use `:` as the separator.
  ///
  /// Returns the complete path after the scheme (e.g., `"web:example.com"`).
  String get path => _uri.path;

  /// The DID method name.
  ///
  /// The method identifies which DID method specification defines the rules
  /// for creating, reading, updating, and deactivating this DID.
  ///
  /// Extracts the method from the DID path by taking the first component
  /// before the first colon.
  ///
  /// Examples:
  /// - `did:web:example.com` → returns `"web"`
  /// - `did:key:z6Mk...` → returns `"key"`
  /// - `did:webvh:z6Mk:example.com` → returns `"webvh"`
  /// - `did:ethr:0x123...` → returns `"ethr"`
  ///
  /// Returns the method name as a string.
  String get method {
    final pathParts = path.split(':');
    return pathParts[0]; // The first part of the path is the method
  }

  /// The complete underlying URI representation.
  ///
  /// Provides access to the full URI object, including all components
  /// such as query parameters and fragments.
  ///
  /// Returns the [Uri] instance that backs this DID.
  ///
  /// Example:
  /// ```dart
  /// final did = DidX.parse('did:web:example.com?service=hub#key-1');
  /// final uri = did.uri;
  /// print(uri.query); // 'service=hub'
  /// print(uri.fragment); // 'key-1'
  /// ```
  Uri get uri => _uri;

  /// The method-specific identifier portion of the DID.
  ///
  /// Extracts everything after the method, including any query parameters
  /// and fragments. The format and content are defined by each DID method
  /// specification.
  ///
  /// This identifier must be unique within the namespace of the DID method.
  ///
  /// Examples:
  /// - `did:web:example.com` → `"example.com"`
  /// - `did:key:z6Mk...` → `"z6Mk..."`
  /// - `did:webvh:z6Mk:example.com` → `"z6Mk:example.com"`
  /// - `did:web:example.com?versionId=1` → `"example.com?versionId=1"`
  /// - `did:web:example.com#key-1` → `"example.com#key-1"`
  ///
  /// Returns the complete method-specific identifier including query and fragment.
  String get methodSpecificId {
    final pathParts = path.split(':');
    final pathStrippedMethod = pathParts
        .sublist(1)
        .join(':'); // Join all parts after the method as the method-specific-id
    final msid =
        '$pathStrippedMethod${_uri.hasQuery ? '?${_uri.query}' : ''}${_uri.hasFragment ? '#${_uri.fragment}' : ''}';
    return msid;
  }

  /// Returns the string representation of this DID.
  ///
  /// Converts the DID back to its canonical string format. This preserves
  /// all components including query parameters and fragments.
  ///
  /// Returns the complete DID string.
  ///
  /// Example:
  /// ```dart
  /// final did = DidX.parse('did:web:example.com?service=hub');
  /// print(did.toString()); // 'did:web:example.com?service=hub'
  /// ```
  @override
  String toString() => _uri.toString();

  /// Tests whether this DID is equal to another object.
  ///
  /// Two [DidX] instances are equal if they wrap equivalent URIs.
  /// This includes matching scheme, method, method-specific identifier,
  /// query parameters, and fragments.
  ///
  /// Parameters:
  /// - [other]: The object to compare with
  ///
  /// Returns `true` if the objects are equal, `false` otherwise.
  ///
  /// Example:
  /// ```dart
  /// final did1 = DidX.parse('did:web:example.com');
  /// final did2 = DidX.parse('did:web:example.com');
  /// print(did1 == did2); // true
  /// ```
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is DidX && runtimeType == other.runtimeType && _uri == other._uri;

  /// Returns the hash code for this DID.
  ///
  /// The hash code is derived from the underlying URI, ensuring that
  /// equal DIDs have the same hash code.
  ///
  /// Returns an integer hash code.
  @override
  int get hashCode => _uri.hashCode;
}

/// A lightweight Decentralized Identifier (DID) implementation that implements the [Uri] interface.
///
/// [Did] provides a streamlined implementation of DIDs specifically optimized for
/// the simplified structure of DID URIs. Unlike standard URIs, DIDs consist of
/// exactly three components without the complexity of authority, host, port, or
/// path segments found in HTTP URLs.
///
/// ## DID Structure
///
/// A DID consists of three parts:
///
/// 1. **scheme**: Always `"did"` - identifies this as a Decentralized Identifier
/// 2. **method**: The DID method name (e.g., `"web"`, `"key"`, `"webvh"`, `"ethr"`)
///    - Specifies which DID method specification defines the resolution rules
/// 3. **methodSpecificId**: The unique identifier within this DID method's namespace
///    - Format and content are defined by each DID method specification
///    - May contain additional colons, paths, or encoded data
///
/// ## DID URI Syntax
///
/// Format: `did:{method}:{method-specific-id}`
///
/// Examples:
/// - `did:web:example.com` - Web-based DID
/// - `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK` - Cryptographic key DID
/// - `did:webvh:z6Mk...ABC:example.com:path` - Web DID with verifiable history
/// - `did:ethr:0x123456789abcdef` - Ethereum-based DID
///
/// ## Key Differences from Standard URI
///
/// Unlike standard [Uri] objects, [Did] instances:
/// - Have no authority, host, port, or userInfo (these concepts don't apply)
/// - Have no path segments (the method-specific-id uses colons, not slashes)
/// - Cannot contain traditional query parameters or fragments as separate components
///   (if present, they're encoded within the method-specific-id)
/// - Cannot be resolved against other URIs using [resolve] or [resolveUri]
/// - Cannot be converted to file system paths using [toFilePath]
///
/// ## Usage Examples
///
/// **Parsing a DID string:**
/// ```dart
/// final did = Did.parse('did:web:example.com');
/// print(did.scheme);           // 'did'
/// print(did.method);           // 'web'
/// print(did.methodSpecificId); // 'example.com'
/// print(did.toString());       // 'did:web:example.com'
/// ```
///
/// **Creating a DID directly:**
/// ```dart
/// final did = Did(
///   scheme: 'did',
///   method: 'key',
///   methodSpecificId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
/// );
/// print(did.toString()); // 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
/// ```
///
/// **Using as a Uri (since Did implements Uri):**
/// ```dart
/// Uri uri = Did.parse('did:web:example.com');
/// if (uri.isScheme('did')) {
///   print('This is a DID!');
/// }
/// ```
///
/// **Resolving a DID (method-specific):**
/// ```dart
/// class DidWeb extends Did {
///   @override
///   Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)> 
///       resolveDid(DidResolutionOptions? options) async {
///     // Implementation for resolving did:web
///   }
/// }
/// ```
///
/// ## Uri Interface Compliance
///
/// [Did] implements the complete [Uri] interface for compatibility. Methods and
/// properties that don't apply to DID URIs throw [UnimplementedError] or
/// [UnsupportedError] with descriptive messages.
///
/// Working methods/properties:
/// - [scheme], [toString()], [isScheme()], [hasScheme]
/// - [operator ==], [hashCode]
///
/// Unsupported methods/properties:
/// - [authority], [host], [port], [userInfo] - DIDs have no authority component
/// - [path], [pathSegments] - DIDs don't use slash-separated paths
/// - [query], [queryParameters] - DIDs don't have separate query components
/// - [fragment] - DIDs don't have separate fragment components
/// - [resolve], [resolveUri] - DIDs aren't resolved against other URIs
/// - [toFilePath] - DIDs don't represent file system paths
///
/// ## See Also
///
/// - [DidX] - Alternative DID implementation using composition instead of interface implementation
/// - [DidDocument] - The resolved DID document containing public keys and service endpoints
/// - W3C DID Core Specification: https://www.w3.org/TR/did-core/
/// - DID Method Registry: https://w3c.github.io/did-spec-registries/#did-methods
class Did implements Uri {
  /// The URI scheme for this DID.
  ///
  /// For all valid DIDs, this will always be exactly `"did"` (lowercase).
  /// This constant value identifies the URI as a Decentralized Identifier
  /// as defined by the W3C DID Core specification.
  ///
  /// This field is immutable after construction.
  @override
  final String scheme;

  /// The DID method name.
  ///
  /// The method identifies which DID method specification governs this DID.
  /// Each DID method defines its own:
  /// - Method-specific identifier format
  /// - Resolution algorithm (how to retrieve the DID Document)
  /// - Create, update, and deactivate operations
  /// - Security and privacy considerations
  ///
  /// Common DID methods include:
  /// - `'web'` - did:web (web-based DIDs hosted on HTTPS domains)
  /// - `'key'` - did:key (DIDs derived directly from cryptographic keys)
  /// - `'webvh'` - did:webvh (web-based DIDs with verifiable history logs)
  /// - `'ethr'` - did:ethr (Ethereum blockchain-based DIDs)
  /// - `'ion'` - did:ion (DIDs on the ION network built on Bitcoin)
  /// - `'peer'` - did:peer (peer-to-peer DIDs for direct communication)
  ///
  /// This field is immutable after construction and must not be empty.
  final String method;

  /// The method-specific identifier.
  ///
  /// This identifier must be unique within the namespace of the DID method.
  /// The format, encoding, and content rules are entirely defined by the
  /// DID method specification.
  ///
  /// Common patterns:
  /// - Domain names (did:web, did:webvh)
  /// - Cryptographic key encodings (did:key)
  /// - Blockchain addresses (did:ethr)
  /// - Hash-based identifiers (did:ion)
  /// - Public key fingerprints (did:peer)
  ///
  /// The identifier may contain:
  /// - Additional colons (`:`) for namespace or path separation
  /// - Percent-encoded characters
  /// - Base58, base64url, or other encodings specified by the method
  ///
  /// Examples:
  /// - For did:web: `'example.com'` or `'example.com:path:to:resource'`
  /// - For did:key: `'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'`
  /// - For did:webvh: `'z6Mk...ABC:example.com:path'`
  /// - For did:ethr: `'0x123456789abcdef'` or `'0x1:0x123456789abcdef'`
  ///
  /// This field is immutable after construction and must not be empty.
  final String methodSpecificId;

  /// Creates a [Did] with the specified DID components.
  ///
  /// This constructor directly creates a DID from its three constituent parts.
  /// It validates that the scheme is `"did"` but does not perform extensive
  /// validation of the method or method-specific identifier.
  ///
  /// **Note**: For parsing DID strings, use [Did.parse] instead, which handles
  /// the string parsing and validation automatically.
  ///
  /// Parameters:
  /// - [scheme]: Must be exactly `"did"` (case-sensitive, lowercase)
  /// - [method]: The DID method name (e.g., `"web"`, `"key"`, `"webvh"`)
  ///   - Should be lowercase alphanumeric
  ///   - Must not be empty
  /// - [methodSpecificId]: The identifier unique within this DID method
  ///   - Format defined by the method specification
  ///   - Must not be empty
  ///
  /// Throws [ArgumentError] if [scheme] is not exactly `"did"`.
  ///
  /// Examples:
  /// ```dart
  /// // Create a did:web DID
  /// final webDid = Did(
  ///   scheme: 'did',
  ///   method: 'web',
  ///   methodSpecificId: 'example.com',
  /// );
  /// print(webDid.toString()); // 'did:web:example.com'
  ///
  /// // Create a did:key DID
  /// final keyDid = Did(
  ///   scheme: 'did',
  ///   method: 'key',
  ///   methodSpecificId: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
  /// );
  /// print(keyDid.toString()); // 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  /// ```
  Did({
    required this.scheme,
    required this.method,
    required this.methodSpecificId,
  }) {
    if (scheme != 'did') {
      throw ArgumentError.value(scheme, 'scheme', 'Must be "did"');
    }
  }

  /// Parses a DID string and returns a [Did] instance.
  ///
  /// This is the **recommended way** to create a [Did] from a string representation.
  /// The parser validates the basic DID format and extracts the three components:
  /// scheme, method, and method-specific identifier.
  ///
  /// ## Expected Format
  ///
  /// `did:{method}:{method-specific-id}`
  ///
  /// Where:
  /// - The scheme must be exactly `"did"`
  /// - The method and method-specific-id must be separated by a colon (`:`)
  /// - Neither the method nor method-specific-id can be empty
  ///
  /// ## Validation
  ///
  /// This parser performs basic structural validation but does **not**:
  /// - Validate method-specific identifier format (this is method-specific)
  /// - Check if the DID method is registered or supported
  /// - Verify cryptographic integrity
  /// - Resolve the DID to check if it exists
  ///
  /// Method-specific validation should be done by the appropriate DID method implementation.
  ///
  /// Parameters:
  /// - [uri]: A string representation of a DID
  ///
  /// Returns a [Did] instance with the parsed components.
  ///
  /// Throws [FormatException] if:
  /// - The string does not start with `'did:'`
  /// - The method component is missing or empty
  /// - The method-specific-id component is missing or empty
  /// - The format doesn't match the expected pattern
  ///
  /// Examples:
  /// ```dart
  /// // Parse various DID methods
  /// final webDid = Did.parse('did:web:example.com');
  /// print(webDid.method); // 'web'
  /// print(webDid.methodSpecificId); // 'example.com'
  ///
  /// final keyDid = Did.parse('did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK');
  /// print(keyDid.method); // 'key'
  /// print(keyDid.methodSpecificId); // 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
  ///
  /// final webvhDid = Did.parse('did:webvh:z6Mk...ABC:example.com:user:alice');
  /// print(webvhDid.method); // 'webvh'
  /// print(webvhDid.methodSpecificId); // 'z6Mk...ABC:example.com:user:alice'
  ///
  /// // Invalid DIDs throw FormatException
  /// try {
  ///   Did.parse('not-a-did'); // Throws FormatException
  /// } catch (e) {
  ///   print(e); // FormatException: Invalid DID: must start with "did:"
  /// }
  /// ```
  factory Did.parse(String uri) {
    if (!uri.startsWith('did:')) {
      throw FormatException('Invalid DID: must start with "did:"', uri);
    }

    final withoutScheme = uri.substring(4); // Remove "did:"
    final colonIndex = withoutScheme.indexOf(':');

    if (colonIndex == -1) {
      throw FormatException(
        'Invalid DID: must contain method and method-specific-id',
        uri,
      );
    }

    final method = withoutScheme.substring(0, colonIndex);
    final methodSpecificId = withoutScheme.substring(colonIndex + 1);

    if (method.isEmpty) {
      throw FormatException('Invalid DID: method cannot be empty', uri);
    }
    if (methodSpecificId.isEmpty) {
      throw FormatException(
        'Invalid DID: method-specific-id cannot be empty',
        uri,
      );
    }

    return Did(
      scheme: 'did',
      method: method,
      methodSpecificId: methodSpecificId,
    );
  }

  /// Resolves this DID to retrieve its associated DID Document.
  ///
  /// DID resolution is the process of obtaining the DID Document associated with
  /// a DID. The resolution process is defined by each DID method specification and
  /// typically involves:
  /// 1. Parsing and validating the DID
  /// 2. Looking up or computing the DID Document
  /// 3. Verifying any cryptographic proofs
  /// 4. Returning the document with metadata
  ///
  /// ## Implementation Note
  ///
  /// This method **must be overridden** by subclasses that implement specific DID methods.
  /// The base [Did] class does not provide resolution functionality because resolution
  /// logic varies significantly between DID methods:
  ///
  /// - **did:web** resolves by fetching a JSON file over HTTPS
  /// - **did:key** derives the document directly from the key
  /// - **did:webvh** fetches and verifies a log file over HTTPS
  /// - **did:ethr** queries the Ethereum blockchain
  /// - **did:ion** queries the ION network and Bitcoin blockchain
  ///
  /// ## Parameters
  ///
  /// - [options]: Optional resolution options (can be `null`). Common options include:
  ///   - `accept`: Preferred media type for the DID Document
  ///   - `versionId`: Request a specific version
  ///   - `versionTime`: Request the version valid at a specific time
  ///   - Method-specific options
  ///
  /// ## Return Value
  ///
  /// Returns a tuple (record) containing three components:
  ///
  /// 1. **DidDocument**: The resolved DID Document containing:
  ///    - Verification methods (public keys)
  ///    - Authentication methods
  ///    - Service endpoints
  ///    - Other DID Document properties
  ///
  /// 2. **DidDocumentMetadata** (nullable): Metadata about the DID Document:
  ///    - `created`: When the DID was created
  ///    - `updated`: When last updated
  ///    - `deactivated`: Whether the DID is deactivated
  ///    - `versionId`: Current version identifier
  ///    - Method-specific metadata
  ///
  /// 3. **DidResolutionMetadata** (nullable): Metadata about the resolution:
  ///    - `contentType`: Media type of the returned document
  ///    - `error`: Error code if resolution failed
  ///    - `message`: Human-readable error message
  ///
  /// ## Exceptions
  ///
  /// The base implementation throws [UnimplementedError]. Subclasses should:
  /// - Throw [SsiDidResolutionException] for resolution failures
  /// - Include error details in the resolution metadata
  /// - Handle network errors, parsing errors, and validation errors
  ///
  /// ## Example Implementation
  ///
  /// ```dart
  /// class DidWeb extends Did {
  ///   DidWeb({required super.scheme, required super.method, required super.methodSpecificId});
  ///
  ///   @override
  ///   Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)> 
  ///       resolveDid([DidResolutionOptions? options]) async {
  ///     // Convert did:web:example.com to https://example.com/.well-known/did.json
  ///     final url = _convertDidToUrl();
  ///     
  ///     // Fetch the DID Document
  ///     final response = await http.get(url);
  ///     final doc = DidDocument.fromJson(jsonDecode(response.body));
  ///     
  ///     // Return with metadata
  ///     return (doc, null, {'contentType': 'application/did+json'});
  ///   }
  /// }
  /// ```
  ///
  /// ## Example Usage
  ///
  /// ```dart
  /// final did = DidWeb.parse('did:web:example.com');
  /// final (document, docMetadata, resolutionMetadata) = await did.resolveDid();
  /// 
  /// print('DID ID: ${document.id}');
  /// print('Verification Methods: ${document.verificationMethod?.length}');
  /// if (docMetadata?['deactivated'] == true) {
  ///   print('Warning: This DID has been deactivated');
  /// }
  /// ```
  ///
  /// See also:
  /// - [DidDocument] - The structure of a DID Document
  /// - [DidResolutionOptions] - Options for controlling resolution
  /// - W3C DID Resolution Specification: https://w3c-ccg.github.io/did-resolution/
  Future<(DidDocument, DidDocumentMetadata?, DidResolutionMetadata?)> resolveDid(
      [DidResolutionOptions? options]) async {
    throw UnimplementedError(
        'resolveDid() is not implemented in the base Did class. '
        'DID resolution must be implemented by method-specific subclasses.');
  }

  // ============================================================================
  // Uri Interface Implementation
  // ============================================================================
  //
  // The following methods and properties implement the Uri interface.
  // Most of these are not applicable to DID URIs and throw UnimplementedError.
  // Only [scheme], [hasScheme], [isScheme], [toString], [==], and [hashCode]
  // are fully implemented.

  /// Throws [UnimplementedError] - DIDs do not have an authority component.
  ///
  /// The authority component in standard URIs (e.g., `user@host:port` in
  /// `http://user@host:port/path`) is not applicable to DIDs, which follow
  /// the format `did:{method}:{method-specific-id}`.
  @override
  String get authority =>
      throw UnimplementedError('DIDs do not have an authority component');

  /// Throws [UnimplementedError] - DIDs do not have a data component.
  ///
  /// Data URIs (e.g., `data:text/plain;base64,SGVsbG8=`) are a different URI
  /// scheme and not applicable to DIDs.
  @override
  UriData? get data =>
      throw UnimplementedError('DIDs do not have a data component');

  /// Throws [UnimplementedError] - DIDs do not have a separate fragment component.
  ///
  /// While DID URLs (extended DIDs) can have fragments for referencing specific
  /// parts of a DID Document (e.g., `did:example:123#key-1`), this implementation
  /// treats them as part of the method-specific identifier, not as a separate
  /// component.
  @override
  String get fragment =>
      throw UnimplementedError('DIDs do not have a separate fragment component');

  /// Throws [UnimplementedError] - DIDs do not use slash-separated paths.
  ///
  /// The concept of an "absolute path" (starting with `/`) doesn't apply to DIDs.
  @override
  bool get hasAbsolutePath =>
      throw UnimplementedError('DIDs do not have slash-separated paths');

  /// Throws [UnimplementedError] - DIDs do not have an authority component.
  @override
  bool get hasAuthority =>
      throw UnimplementedError('DIDs do not have an authority component');

  /// Throws [UnimplementedError] - DIDs do not have a separate path component.
  @override
  bool get hasEmptyPath =>
      throw UnimplementedError('DIDs do not have a separate path component');

  /// Throws [UnimplementedError] - DIDs do not have a separate fragment component.
  @override
  bool get hasFragment =>
      throw UnimplementedError('DIDs do not have a separate fragment component');

  /// Throws [UnimplementedError] - DIDs do not have a port number.
  @override
  bool get hasPort =>
      throw UnimplementedError('DIDs do not have a port component');

  /// Throws [UnimplementedError] - DIDs do not have a separate query component.
  @override
  bool get hasQuery =>
      throw UnimplementedError('DIDs do not have a separate query component');

  /// Always returns `true` since all DIDs have the "did" scheme.
  ///
  /// This is a constant property for DIDs - the scheme is always present
  /// and always equals "did".
  @override
  bool get hasScheme => true;

  /// Throws [UnimplementedError] - DIDs do not have a host component.
  ///
  /// The host component in HTTP URLs (e.g., `example.com` in `https://example.com/path`)
  /// has no equivalent in DIDs.
  @override
  String get host =>
      throw UnimplementedError('DIDs do not have a host component');

  /// Throws [UnimplementedError] - DIDs don't distinguish between absolute and relative.
  ///
  /// All DIDs are self-contained identifiers and don't have the concept of
  /// relative vs. absolute paths.
  @override
  bool get isAbsolute =>
      throw UnimplementedError('DIDs are always self-contained identifiers');

  /// Tests whether this DID URI has the specified scheme.
  ///
  /// For DIDs, this will return `true` only when testing for "did".
  /// The comparison is case-sensitive.
  ///
  /// Parameters:
  /// - [scheme]: The scheme to test against (typically "did")
  ///
  /// Returns `true` if the schemes match exactly, `false` otherwise.
  ///
  /// Example:
  /// ```dart
  /// final did = Did.parse('did:web:example.com');
  /// print(did.isScheme('did')); // true
  /// print(did.isScheme('http')); // false
  /// print(did.isScheme('DID')); // false (case-sensitive)
  /// ```
  @override
  bool isScheme(String scheme) => this.scheme == scheme;

  /// Throws [UnimplementedError] - DIDs do not have paths to normalize.
  ///
  /// Path normalization (removing `.` and `..` segments) applies to hierarchical
  /// URIs with slash-separated paths, not to DIDs.
  @override
  Uri normalizePath() =>
      throw UnimplementedError('DIDs do not have paths to normalize');

  /// Throws [UnimplementedError] - DIDs do not have an origin.
  ///
  /// The origin concept (e.g., `https://example.com` from `https://example.com/path`)
  /// applies to HTTP URLs, not to DIDs.
  @override
  String get origin =>
      throw UnimplementedError('DIDs do not have an origin component');

  /// Throws [UnimplementedError] - DIDs do not have a separate path component.
  ///
  /// The method-specific identifier uses colons as separators, not slashes,
  /// so the concept of a "path" doesn't apply.
  @override
  String get path =>
      throw UnimplementedError('DIDs do not have a separate path component');

  /// Throws [UnimplementedError] - DIDs do not have path segments.
  ///
  /// Path segments (e.g., `['path', 'to', 'file']` from `/path/to/file`) don't
  /// apply to DIDs which use colons instead of slashes.
  @override
  List<String> get pathSegments =>
      throw UnimplementedError('DIDs do not have path segments');

  /// Throws [UnimplementedError] - DIDs do not have a port number.
  @override
  int get port =>
      throw UnimplementedError('DIDs do not have a port component');

  /// Throws [UnimplementedError] - DIDs do not have a separate query string.
  ///
  /// If present, query-like components are part of the method-specific identifier.
  @override
  String get query =>
      throw UnimplementedError('DIDs do not have a separate query component');

  /// Throws [UnimplementedError] - DIDs do not have query parameters as a map.
  @override
  Map<String, String> get queryParameters =>
      throw UnimplementedError('DIDs do not have separate query parameters');

  /// Throws [UnimplementedError] - DIDs do not have query parameters.
  @override
  Map<String, List<String>> get queryParametersAll =>
      throw UnimplementedError('DIDs do not have separate query parameters');

  /// Throws [UnimplementedError] - DIDs do not have fragments to remove.
  @override
  Uri removeFragment() =>
      throw UnimplementedError('DIDs do not have separate fragments to remove');

  /// Throws [UnimplementedError] - DIDs cannot be modified using replace().
  ///
  /// The [replace] method is used to create modified copies of HTTP URLs.
  /// DIDs are immutable identifiers and cannot be "replaced" in this way.
  /// To create a new DID, use the [Did] constructor or [Did.parse].
  @override
  Uri replace({
    String? scheme,
    String? userInfo,
    String? host,
    int? port,
    String? path,
    Iterable<String>? pathSegments,
    String? query,
    Map<String, dynamic>? queryParameters,
    String? fragment,
  }) =>
      throw UnimplementedError('DIDs cannot be modified using replace()');

  /// Throws [UnimplementedError] - DIDs cannot resolve references.
  ///
  /// The [resolve] method is used for resolving relative URIs against a base URI
  /// (e.g., resolving `path/file` against `http://example.com/base/`).
  /// This concept doesn't apply to DIDs.
  @override
  Uri resolve(String reference) =>
      throw UnimplementedError('DIDs cannot resolve relative references');

  /// Throws [UnimplementedError] - DIDs cannot resolve URI references.
  ///
  /// Similar to [resolve], but takes a Uri object instead of a string.
  /// This operation is not applicable to DIDs.
  @override
  Uri resolveUri(Uri reference) =>
      throw UnimplementedError('DIDs cannot resolve URI references');

  /// Throws [UnsupportedError] - DIDs cannot be converted to file system paths.
  ///
  /// The [toFilePath] method converts file:// URIs to operating system file paths.
  /// DIDs represent decentralized identifiers, not file system locations, so this
  /// operation has no meaningful interpretation.
  ///
  /// Parameters:
  /// - [windows]: Whether to use Windows-style paths (ignored, will throw anyway)
  ///
  /// Throws [UnsupportedError] always.
  @override
  String toFilePath({bool? windows}) =>
      throw UnsupportedError('DIDs cannot be converted to file system paths');

  /// Returns the string representation of this DID.
  ///
  /// Converts the DID back to its canonical string format:
  /// `did:{method}:{method-specific-id}`
  ///
  /// This is the inverse of [Did.parse] - parsing a DID string and converting
  /// it back to a string produces the original input.
  ///
  /// Returns the complete DID string.
  ///
  /// Examples:
  /// ```dart
  /// final did = Did.parse('did:web:example.com');
  /// print(did.toString()); // 'did:web:example.com'
  ///
  /// final keyDid = Did(
  ///   scheme: 'did',
  ///   method: 'key',
  ///   methodSpecificId: 'z6Mk...',
  /// );
  /// print(keyDid.toString()); // 'did:key:z6Mk...'
  /// ```
  @override
  String toString() => '$scheme:$method:$methodSpecificId';

  /// Throws [UnimplementedError] - DIDs do not have a userInfo component.
  ///
  /// The userInfo component in HTTP URLs (e.g., `user:password` in
  /// `https://user:password@example.com`) is used for authentication credentials.
  /// Since DIDs don't have an authority component and follow the format
  /// `did:{method}:{method-specific-id}`, userInfo is not applicable.
  @override
  String get userInfo =>
      throw UnimplementedError('DIDs do not have a userInfo component');

  /// Tests whether this DID is equal to another object.
  ///
  /// Two [Did] instances are considered equal if and only if they have:
  /// - The same scheme (always "did")
  /// - The same method (case-sensitive)
  /// - The same method-specific identifier (case-sensitive)
  ///
  /// **Important**: Equality is based on string comparison, not semantic equivalence.
  /// Different string representations of the same logical DID are not considered equal
  /// unless they're identical. DID method specifications may define normalization
  /// rules, but this implementation doesn't apply them automatically.
  ///
  /// Parameters:
  /// - [other]: The object to compare with
  ///
  /// Returns `true` if the DIDs are equal, `false` otherwise.
  ///
  /// Examples:
  /// ```dart
  /// final did1 = Did.parse('did:web:example.com');
  /// final did2 = Did.parse('did:web:example.com');
  /// final did3 = Did.parse('did:web:Example.com'); // Different case
  /// 
  /// print(did1 == did2); // true (identical strings)
  /// print(did1 == did3); // false (different case in identifier)
  /// print(did1 == 'did:web:example.com'); // false (different type)
  /// ```
  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Did &&
          scheme == other.scheme &&
          method == other.method &&
          methodSpecificId == other.methodSpecificId;

  /// Returns the hash code for this DID.
  ///
  /// The hash code is computed from all three DID components: scheme, method,
  /// and method-specific identifier. Equal DIDs will always have the same hash code.
  ///
  /// This enables DIDs to be used in hash-based collections like [Set] and [Map].
  ///
  /// Returns an integer hash code.
  ///
  /// Example:
  /// ```dart
  /// final dids = <Did>{};
  /// dids.add(Did.parse('did:web:example.com'));
  /// print(dids.contains(Did.parse('did:web:example.com'))); // true
  /// ```
  @override
  int get hashCode => Object.hash(scheme, method, methodSpecificId);
}
