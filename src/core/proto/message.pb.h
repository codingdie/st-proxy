// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: message.proto

#ifndef PROTOBUF_INCLUDED_message_2eproto
#define PROTOBUF_INCLUDED_message_2eproto

#include <limits>
#include <string>

#include <google/protobuf/port_def.inc>
#if PROTOBUF_VERSION < 3007000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers. Please update
#error your headers.
#endif
#if 3007001 < PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers. Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/port_undef.inc>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/arena.h>
#include <google/protobuf/arenastring.h>
#include <google/protobuf/generated_message_table_driven.h>
#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/inlined_string_field.h>
#include <google/protobuf/metadata_lite.h>
#include <google/protobuf/message_lite.h>
#include <google/protobuf/repeated_field.h>  // IWYU pragma: export
#include <google/protobuf/extension_set.h>  // IWYU pragma: export
#include <google/protobuf/generated_enum_util.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>
#define PROTOBUF_INTERNAL_EXPORT_message_2eproto

// Internal implementation detail -- do not use these members.
struct TableStruct_message_2eproto {
  static const ::google::protobuf::internal::ParseTableField entries[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::google::protobuf::internal::AuxillaryParseTableField aux[]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::google::protobuf::internal::ParseTable schema[2]
    PROTOBUF_SECTION_VARIABLE(protodesc_cold);
  static const ::google::protobuf::internal::FieldMetadata field_metadata[];
  static const ::google::protobuf::internal::SerializationTable serialization_table[];
  static const ::google::protobuf::uint32 offsets[];
};
namespace st {
namespace proxy {
namespace proto {
class quality_record;
class quality_recordDefaultTypeInternal;
extern quality_recordDefaultTypeInternal _quality_record_default_instance_;
class session_record;
class session_recordDefaultTypeInternal;
extern session_recordDefaultTypeInternal _session_record_default_instance_;
}  // namespace proto
}  // namespace proxy
}  // namespace st
namespace google {
namespace protobuf {
template<> ::st::proxy::proto::quality_record* Arena::CreateMaybeMessage<::st::proxy::proto::quality_record>(Arena*);
template<> ::st::proxy::proto::session_record* Arena::CreateMaybeMessage<::st::proxy::proto::session_record>(Arena*);
}  // namespace protobuf
}  // namespace google
namespace st {
namespace proxy {
namespace proto {

enum record_type {
  IP_TUNNEL = 0,
  IP = 1,
  record_type_INT_MIN_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::google::protobuf::int32>::min(),
  record_type_INT_MAX_SENTINEL_DO_NOT_USE_ = std::numeric_limits<::google::protobuf::int32>::max()
};
bool record_type_IsValid(int value);
const record_type record_type_MIN = IP_TUNNEL;
const record_type record_type_MAX = IP;
const int record_type_ARRAYSIZE = record_type_MAX + 1;

// ===================================================================

class session_record :
    public ::google::protobuf::MessageLite /* @@protoc_insertion_point(class_definition:st.proxy.proto.session_record) */ {
 public:
  session_record();
  virtual ~session_record();

  session_record(const session_record& from);

  inline session_record& operator=(const session_record& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  session_record(session_record&& from) noexcept
    : session_record() {
    *this = ::std::move(from);
  }

  inline session_record& operator=(session_record&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const session_record& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const session_record* internal_default_instance() {
    return reinterpret_cast<const session_record*>(
               &_session_record_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    0;

  void Swap(session_record* other);
  friend void swap(session_record& a, session_record& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline session_record* New() const final {
    return CreateMaybeMessage<session_record>(nullptr);
  }

  session_record* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<session_record>(arena);
  }
  void CheckTypeAndMergeFrom(const ::google::protobuf::MessageLite& from)
    final;
  void CopyFrom(const session_record& from);
  void MergeFrom(const session_record& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  #if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
  static const char* _InternalParse(const char* begin, const char* end, void* object, ::google::protobuf::internal::ParseContext* ctx);
  ::google::protobuf::internal::ParseFunc _ParseFunc() const final { return _InternalParse; }
  #else
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  #endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  void DiscardUnknownFields();
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  void InternalSwap(session_record* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::std::string GetTypeName() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // bool success = 1;
  void clear_success();
  static const int kSuccessFieldNumber = 1;
  bool success() const;
  void set_success(bool value);

  // uint32 first_package_cost = 2;
  void clear_first_package_cost();
  static const int kFirstPackageCostFieldNumber = 2;
  ::google::protobuf::uint32 first_package_cost() const;
  void set_first_package_cost(::google::protobuf::uint32 value);

  // uint64 timestamp = 3;
  void clear_timestamp();
  static const int kTimestampFieldNumber = 3;
  ::google::protobuf::uint64 timestamp() const;
  void set_timestamp(::google::protobuf::uint64 value);

  // @@protoc_insertion_point(class_scope:st.proxy.proto.session_record)
 private:
  class HasBitSetters;

  ::google::protobuf::internal::InternalMetadataWithArenaLite _internal_metadata_;
  bool success_;
  ::google::protobuf::uint32 first_package_cost_;
  ::google::protobuf::uint64 timestamp_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_message_2eproto;
};
// -------------------------------------------------------------------

class quality_record :
    public ::google::protobuf::MessageLite /* @@protoc_insertion_point(class_definition:st.proxy.proto.quality_record) */ {
 public:
  quality_record();
  virtual ~quality_record();

  quality_record(const quality_record& from);

  inline quality_record& operator=(const quality_record& from) {
    CopyFrom(from);
    return *this;
  }
  #if LANG_CXX11
  quality_record(quality_record&& from) noexcept
    : quality_record() {
    *this = ::std::move(from);
  }

  inline quality_record& operator=(quality_record&& from) noexcept {
    if (GetArenaNoVirtual() == from.GetArenaNoVirtual()) {
      if (this != &from) InternalSwap(&from);
    } else {
      CopyFrom(from);
    }
    return *this;
  }
  #endif
  static const quality_record& default_instance();

  static void InitAsDefaultInstance();  // FOR INTERNAL USE ONLY
  static inline const quality_record* internal_default_instance() {
    return reinterpret_cast<const quality_record*>(
               &_quality_record_default_instance_);
  }
  static constexpr int kIndexInFileMessages =
    1;

  void Swap(quality_record* other);
  friend void swap(quality_record& a, quality_record& b) {
    a.Swap(&b);
  }

  // implements Message ----------------------------------------------

  inline quality_record* New() const final {
    return CreateMaybeMessage<quality_record>(nullptr);
  }

  quality_record* New(::google::protobuf::Arena* arena) const final {
    return CreateMaybeMessage<quality_record>(arena);
  }
  void CheckTypeAndMergeFrom(const ::google::protobuf::MessageLite& from)
    final;
  void CopyFrom(const quality_record& from);
  void MergeFrom(const quality_record& from);
  PROTOBUF_ATTRIBUTE_REINITIALIZES void Clear() final;
  bool IsInitialized() const final;

  size_t ByteSizeLong() const final;
  #if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
  static const char* _InternalParse(const char* begin, const char* end, void* object, ::google::protobuf::internal::ParseContext* ctx);
  ::google::protobuf::internal::ParseFunc _ParseFunc() const final { return _InternalParse; }
  #else
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input) final;
  #endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const final;
  void DiscardUnknownFields();
  int GetCachedSize() const final { return _cached_size_.Get(); }

  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  void InternalSwap(quality_record* other);
  private:
  inline ::google::protobuf::Arena* GetArenaNoVirtual() const {
    return nullptr;
  }
  inline void* MaybeArenaPtr() const {
    return nullptr;
  }
  public:

  ::std::string GetTypeName() const final;

  // nested types ----------------------------------------------------

  // accessors -------------------------------------------------------

  // repeated .st.proxy.proto.session_record records = 1;
  int records_size() const;
  void clear_records();
  static const int kRecordsFieldNumber = 1;
  ::st::proxy::proto::session_record* mutable_records(int index);
  ::google::protobuf::RepeatedPtrField< ::st::proxy::proto::session_record >*
      mutable_records();
  const ::st::proxy::proto::session_record& records(int index) const;
  ::st::proxy::proto::session_record* add_records();
  const ::google::protobuf::RepeatedPtrField< ::st::proxy::proto::session_record >&
      records() const;

  // uint32 queue_size = 2;
  void clear_queue_size();
  static const int kQueueSizeFieldNumber = 2;
  ::google::protobuf::uint32 queue_size() const;
  void set_queue_size(::google::protobuf::uint32 value);

  // uint32 first_package_cost = 3;
  void clear_first_package_cost();
  static const int kFirstPackageCostFieldNumber = 3;
  ::google::protobuf::uint32 first_package_cost() const;
  void set_first_package_cost(::google::protobuf::uint32 value);

  // uint32 first_package_success = 4;
  void clear_first_package_success();
  static const int kFirstPackageSuccessFieldNumber = 4;
  ::google::protobuf::uint32 first_package_success() const;
  void set_first_package_success(::google::protobuf::uint32 value);

  // uint32 first_package_failed = 5;
  void clear_first_package_failed();
  static const int kFirstPackageFailedFieldNumber = 5;
  ::google::protobuf::uint32 first_package_failed() const;
  void set_first_package_failed(::google::protobuf::uint32 value);

  // .st.proxy.proto.record_type type = 6;
  void clear_type();
  static const int kTypeFieldNumber = 6;
  ::st::proxy::proto::record_type type() const;
  void set_type(::st::proxy::proto::record_type value);

  // @@protoc_insertion_point(class_scope:st.proxy.proto.quality_record)
 private:
  class HasBitSetters;

  ::google::protobuf::internal::InternalMetadataWithArenaLite _internal_metadata_;
  ::google::protobuf::RepeatedPtrField< ::st::proxy::proto::session_record > records_;
  ::google::protobuf::uint32 queue_size_;
  ::google::protobuf::uint32 first_package_cost_;
  ::google::protobuf::uint32 first_package_success_;
  ::google::protobuf::uint32 first_package_failed_;
  int type_;
  mutable ::google::protobuf::internal::CachedSize _cached_size_;
  friend struct ::TableStruct_message_2eproto;
};
// ===================================================================


// ===================================================================

#ifdef __GNUC__
  #pragma GCC diagnostic push
  #pragma GCC diagnostic ignored "-Wstrict-aliasing"
#endif  // __GNUC__
// session_record

// bool success = 1;
inline void session_record::clear_success() {
  success_ = false;
}
inline bool session_record::success() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.session_record.success)
  return success_;
}
inline void session_record::set_success(bool value) {
  
  success_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.session_record.success)
}

// uint32 first_package_cost = 2;
inline void session_record::clear_first_package_cost() {
  first_package_cost_ = 0u;
}
inline ::google::protobuf::uint32 session_record::first_package_cost() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.session_record.first_package_cost)
  return first_package_cost_;
}
inline void session_record::set_first_package_cost(::google::protobuf::uint32 value) {
  
  first_package_cost_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.session_record.first_package_cost)
}

// uint64 timestamp = 3;
inline void session_record::clear_timestamp() {
  timestamp_ = PROTOBUF_ULONGLONG(0);
}
inline ::google::protobuf::uint64 session_record::timestamp() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.session_record.timestamp)
  return timestamp_;
}
inline void session_record::set_timestamp(::google::protobuf::uint64 value) {
  
  timestamp_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.session_record.timestamp)
}

// -------------------------------------------------------------------

// quality_record

// repeated .st.proxy.proto.session_record records = 1;
inline int quality_record::records_size() const {
  return records_.size();
}
inline void quality_record::clear_records() {
  records_.Clear();
}
inline ::st::proxy::proto::session_record* quality_record::mutable_records(int index) {
  // @@protoc_insertion_point(field_mutable:st.proxy.proto.quality_record.records)
  return records_.Mutable(index);
}
inline ::google::protobuf::RepeatedPtrField< ::st::proxy::proto::session_record >*
quality_record::mutable_records() {
  // @@protoc_insertion_point(field_mutable_list:st.proxy.proto.quality_record.records)
  return &records_;
}
inline const ::st::proxy::proto::session_record& quality_record::records(int index) const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.records)
  return records_.Get(index);
}
inline ::st::proxy::proto::session_record* quality_record::add_records() {
  // @@protoc_insertion_point(field_add:st.proxy.proto.quality_record.records)
  return records_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::st::proxy::proto::session_record >&
quality_record::records() const {
  // @@protoc_insertion_point(field_list:st.proxy.proto.quality_record.records)
  return records_;
}

// uint32 queue_size = 2;
inline void quality_record::clear_queue_size() {
  queue_size_ = 0u;
}
inline ::google::protobuf::uint32 quality_record::queue_size() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.queue_size)
  return queue_size_;
}
inline void quality_record::set_queue_size(::google::protobuf::uint32 value) {
  
  queue_size_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.quality_record.queue_size)
}

// uint32 first_package_cost = 3;
inline void quality_record::clear_first_package_cost() {
  first_package_cost_ = 0u;
}
inline ::google::protobuf::uint32 quality_record::first_package_cost() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.first_package_cost)
  return first_package_cost_;
}
inline void quality_record::set_first_package_cost(::google::protobuf::uint32 value) {
  
  first_package_cost_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.quality_record.first_package_cost)
}

// uint32 first_package_success = 4;
inline void quality_record::clear_first_package_success() {
  first_package_success_ = 0u;
}
inline ::google::protobuf::uint32 quality_record::first_package_success() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.first_package_success)
  return first_package_success_;
}
inline void quality_record::set_first_package_success(::google::protobuf::uint32 value) {
  
  first_package_success_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.quality_record.first_package_success)
}

// uint32 first_package_failed = 5;
inline void quality_record::clear_first_package_failed() {
  first_package_failed_ = 0u;
}
inline ::google::protobuf::uint32 quality_record::first_package_failed() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.first_package_failed)
  return first_package_failed_;
}
inline void quality_record::set_first_package_failed(::google::protobuf::uint32 value) {
  
  first_package_failed_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.quality_record.first_package_failed)
}

// .st.proxy.proto.record_type type = 6;
inline void quality_record::clear_type() {
  type_ = 0;
}
inline ::st::proxy::proto::record_type quality_record::type() const {
  // @@protoc_insertion_point(field_get:st.proxy.proto.quality_record.type)
  return static_cast< ::st::proxy::proto::record_type >(type_);
}
inline void quality_record::set_type(::st::proxy::proto::record_type value) {
  
  type_ = value;
  // @@protoc_insertion_point(field_set:st.proxy.proto.quality_record.type)
}

#ifdef __GNUC__
  #pragma GCC diagnostic pop
#endif  // __GNUC__
// -------------------------------------------------------------------


// @@protoc_insertion_point(namespace_scope)

}  // namespace proto
}  // namespace proxy
}  // namespace st

namespace google {
namespace protobuf {

template <> struct is_proto_enum< ::st::proxy::proto::record_type> : ::std::true_type {};

}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)

#include <google/protobuf/port_undef.inc>
#endif  // PROTOBUF_INCLUDED_message_2eproto
