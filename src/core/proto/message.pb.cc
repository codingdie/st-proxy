// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: message.proto

#include "message.pb.h"

#include <algorithm>

#include <google/protobuf/stubs/common.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite_inl.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

extern PROTOBUF_INTERNAL_EXPORT_message_2eproto ::google::protobuf::internal::SCCInfo<0> scc_info_session_record_message_2eproto;
namespace st {
namespace proxy {
namespace proto {
class session_recordDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<session_record> _instance;
} _session_record_default_instance_;
class quality_recordDefaultTypeInternal {
 public:
  ::google::protobuf::internal::ExplicitlyConstructed<quality_record> _instance;
} _quality_record_default_instance_;
}  // namespace proto
}  // namespace proxy
}  // namespace st
static void InitDefaultssession_record_message_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::st::proxy::proto::_session_record_default_instance_;
    new (ptr) ::st::proxy::proto::session_record();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::st::proxy::proto::session_record::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<0> scc_info_session_record_message_2eproto =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 0, InitDefaultssession_record_message_2eproto}, {}};

static void InitDefaultsquality_record_message_2eproto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  {
    void* ptr = &::st::proxy::proto::_quality_record_default_instance_;
    new (ptr) ::st::proxy::proto::quality_record();
    ::google::protobuf::internal::OnShutdownDestroyMessage(ptr);
  }
  ::st::proxy::proto::quality_record::InitAsDefaultInstance();
}

::google::protobuf::internal::SCCInfo<1> scc_info_quality_record_message_2eproto =
    {{ATOMIC_VAR_INIT(::google::protobuf::internal::SCCInfoBase::kUninitialized), 1, InitDefaultsquality_record_message_2eproto}, {
      &scc_info_session_record_message_2eproto.base,}};

namespace st {
namespace proxy {
namespace proto {
bool record_type_IsValid(int value) {
  switch (value) {
    case 0:
    case 1:
      return true;
    default:
      return false;
  }
}


// ===================================================================

void session_record::InitAsDefaultInstance() {
}
class session_record::HasBitSetters {
 public:
};

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int session_record::kSuccessFieldNumber;
const int session_record::kFirstPackageCostFieldNumber;
const int session_record::kTimestampFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

session_record::session_record()
  : ::google::protobuf::MessageLite(), _internal_metadata_(nullptr) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:st.proxy.proto.session_record)
}
session_record::session_record(const session_record& from)
  : ::google::protobuf::MessageLite(),
      _internal_metadata_(nullptr) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::memcpy(&success_, &from.success_,
    static_cast<size_t>(reinterpret_cast<char*>(&timestamp_) -
    reinterpret_cast<char*>(&success_)) + sizeof(timestamp_));
  // @@protoc_insertion_point(copy_constructor:st.proxy.proto.session_record)
}

void session_record::SharedCtor() {
  ::memset(&success_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&timestamp_) -
      reinterpret_cast<char*>(&success_)) + sizeof(timestamp_));
}

session_record::~session_record() {
  // @@protoc_insertion_point(destructor:st.proxy.proto.session_record)
  SharedDtor();
}

void session_record::SharedDtor() {
}

void session_record::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const session_record& session_record::default_instance() {
  ::google::protobuf::internal::InitSCC(&::scc_info_session_record_message_2eproto.base);
  return *internal_default_instance();
}


void session_record::Clear() {
// @@protoc_insertion_point(message_clear_start:st.proxy.proto.session_record)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  ::memset(&success_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&timestamp_) -
      reinterpret_cast<char*>(&success_)) + sizeof(timestamp_));
  _internal_metadata_.Clear();
}

#if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
const char* session_record::_InternalParse(const char* begin, const char* end, void* object,
                  ::google::protobuf::internal::ParseContext* ctx) {
  auto msg = static_cast<session_record*>(object);
  ::google::protobuf::int32 size; (void)size;
  int depth; (void)depth;
  ::google::protobuf::uint32 tag;
  ::google::protobuf::internal::ParseFunc parser_till_end; (void)parser_till_end;
  auto ptr = begin;
  while (ptr < end) {
    ptr = ::google::protobuf::io::Parse32(ptr, &tag);
    GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
    switch (tag >> 3) {
      // bool success = 1;
      case 1: {
        if (static_cast<::google::protobuf::uint8>(tag) != 8) goto handle_unusual;
        msg->set_success(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // uint32 first_package_cost = 2;
      case 2: {
        if (static_cast<::google::protobuf::uint8>(tag) != 16) goto handle_unusual;
        msg->set_first_package_cost(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // uint64 timestamp = 3;
      case 3: {
        if (static_cast<::google::protobuf::uint8>(tag) != 24) goto handle_unusual;
        msg->set_timestamp(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->EndGroup(tag);
          return ptr;
        }
        auto res = UnknownFieldParse(tag, {_InternalParse, msg},
          ptr, end, msg->_internal_metadata_.mutable_unknown_fields(), ctx);
        ptr = res.first;
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr != nullptr);
        if (res.second) return ptr;
      }
    }  // switch
  }  // while
  return ptr;
}
#else  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
bool session_record::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!PROTOBUF_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  ::google::protobuf::internal::LiteUnknownFieldSetter unknown_fields_setter(
      &_internal_metadata_);
  ::google::protobuf::io::StringOutputStream unknown_fields_output(
      unknown_fields_setter.buffer());
  ::google::protobuf::io::CodedOutputStream unknown_fields_stream(
      &unknown_fields_output, false);
  // @@protoc_insertion_point(parse_start:st.proxy.proto.session_record)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // bool success = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (8 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   bool, ::google::protobuf::internal::WireFormatLite::TYPE_BOOL>(
                 input, &success_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint32 first_package_cost = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (16 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &first_package_cost_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint64 timestamp = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (24 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint64, ::google::protobuf::internal::WireFormatLite::TYPE_UINT64>(
                 input, &timestamp_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(
            input, tag, &unknown_fields_stream));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:st.proxy.proto.session_record)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:st.proxy.proto.session_record)
  return false;
#undef DO_
}
#endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER

void session_record::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:st.proxy.proto.session_record)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // bool success = 1;
  if (this->success() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteBool(1, this->success(), output);
  }

  // uint32 first_package_cost = 2;
  if (this->first_package_cost() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(2, this->first_package_cost(), output);
  }

  // uint64 timestamp = 3;
  if (this->timestamp() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt64(3, this->timestamp(), output);
  }

  output->WriteRaw(_internal_metadata_.unknown_fields().data(),
                   static_cast<int>(_internal_metadata_.unknown_fields().size()));
  // @@protoc_insertion_point(serialize_end:st.proxy.proto.session_record)
}

size_t session_record::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:st.proxy.proto.session_record)
  size_t total_size = 0;

  total_size += _internal_metadata_.unknown_fields().size();

  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // bool success = 1;
  if (this->success() != 0) {
    total_size += 1 + 1;
  }

  // uint32 first_package_cost = 2;
  if (this->first_package_cost() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt32Size(
        this->first_package_cost());
  }

  // uint64 timestamp = 3;
  if (this->timestamp() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt64Size(
        this->timestamp());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void session_record::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::google::protobuf::down_cast<const session_record*>(&from));
}

void session_record::MergeFrom(const session_record& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:st.proxy.proto.session_record)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  if (from.success() != 0) {
    set_success(from.success());
  }
  if (from.first_package_cost() != 0) {
    set_first_package_cost(from.first_package_cost());
  }
  if (from.timestamp() != 0) {
    set_timestamp(from.timestamp());
  }
}

void session_record::CopyFrom(const session_record& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:st.proxy.proto.session_record)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool session_record::IsInitialized() const {
  return true;
}

void session_record::Swap(session_record* other) {
  if (other == this) return;
  InternalSwap(other);
}
void session_record::InternalSwap(session_record* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
  swap(success_, other->success_);
  swap(first_package_cost_, other->first_package_cost_);
  swap(timestamp_, other->timestamp_);
}

::std::string session_record::GetTypeName() const {
  return "st.proxy.proto.session_record";
}


// ===================================================================

void quality_record::InitAsDefaultInstance() {
}
class quality_record::HasBitSetters {
 public:
};

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const int quality_record::kRecordsFieldNumber;
const int quality_record::kQueueSizeFieldNumber;
const int quality_record::kFirstPackageCostFieldNumber;
const int quality_record::kFirstPackageSuccessFieldNumber;
const int quality_record::kFirstPackageFailedFieldNumber;
const int quality_record::kTypeFieldNumber;
#endif  // !defined(_MSC_VER) || _MSC_VER >= 1900

quality_record::quality_record()
  : ::google::protobuf::MessageLite(), _internal_metadata_(nullptr) {
  SharedCtor();
  // @@protoc_insertion_point(constructor:st.proxy.proto.quality_record)
}
quality_record::quality_record(const quality_record& from)
  : ::google::protobuf::MessageLite(),
      _internal_metadata_(nullptr),
      records_(from.records_) {
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::memcpy(&queue_size_, &from.queue_size_,
    static_cast<size_t>(reinterpret_cast<char*>(&type_) -
    reinterpret_cast<char*>(&queue_size_)) + sizeof(type_));
  // @@protoc_insertion_point(copy_constructor:st.proxy.proto.quality_record)
}

void quality_record::SharedCtor() {
  ::google::protobuf::internal::InitSCC(
      &scc_info_quality_record_message_2eproto.base);
  ::memset(&queue_size_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&type_) -
      reinterpret_cast<char*>(&queue_size_)) + sizeof(type_));
}

quality_record::~quality_record() {
  // @@protoc_insertion_point(destructor:st.proxy.proto.quality_record)
  SharedDtor();
}

void quality_record::SharedDtor() {
}

void quality_record::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}
const quality_record& quality_record::default_instance() {
  ::google::protobuf::internal::InitSCC(&::scc_info_quality_record_message_2eproto.base);
  return *internal_default_instance();
}


void quality_record::Clear() {
// @@protoc_insertion_point(message_clear_start:st.proxy.proto.quality_record)
  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  records_.Clear();
  ::memset(&queue_size_, 0, static_cast<size_t>(
      reinterpret_cast<char*>(&type_) -
      reinterpret_cast<char*>(&queue_size_)) + sizeof(type_));
  _internal_metadata_.Clear();
}

#if GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
const char* quality_record::_InternalParse(const char* begin, const char* end, void* object,
                  ::google::protobuf::internal::ParseContext* ctx) {
  auto msg = static_cast<quality_record*>(object);
  ::google::protobuf::int32 size; (void)size;
  int depth; (void)depth;
  ::google::protobuf::uint32 tag;
  ::google::protobuf::internal::ParseFunc parser_till_end; (void)parser_till_end;
  auto ptr = begin;
  while (ptr < end) {
    ptr = ::google::protobuf::io::Parse32(ptr, &tag);
    GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
    switch (tag >> 3) {
      // repeated .st.proxy.proto.session_record records = 1;
      case 1: {
        if (static_cast<::google::protobuf::uint8>(tag) != 10) goto handle_unusual;
        do {
          ptr = ::google::protobuf::io::ReadSize(ptr, &size);
          GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
          parser_till_end = ::st::proxy::proto::session_record::_InternalParse;
          object = msg->add_records();
          if (size > end - ptr) goto len_delim_till_end;
          ptr += size;
          GOOGLE_PROTOBUF_PARSER_ASSERT(ctx->ParseExactRange(
              {parser_till_end, object}, ptr - size, ptr));
          if (ptr >= end) break;
        } while ((::google::protobuf::io::UnalignedLoad<::google::protobuf::uint64>(ptr) & 255) == 10 && (ptr += 1));
        break;
      }
      // uint32 queue_size = 2;
      case 2: {
        if (static_cast<::google::protobuf::uint8>(tag) != 16) goto handle_unusual;
        msg->set_queue_size(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // uint32 first_package_cost = 3;
      case 3: {
        if (static_cast<::google::protobuf::uint8>(tag) != 24) goto handle_unusual;
        msg->set_first_package_cost(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // uint32 first_package_success = 4;
      case 4: {
        if (static_cast<::google::protobuf::uint8>(tag) != 32) goto handle_unusual;
        msg->set_first_package_success(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // uint32 first_package_failed = 5;
      case 5: {
        if (static_cast<::google::protobuf::uint8>(tag) != 40) goto handle_unusual;
        msg->set_first_package_failed(::google::protobuf::internal::ReadVarint(&ptr));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      // .st.proxy.proto.record_type type = 6;
      case 6: {
        if (static_cast<::google::protobuf::uint8>(tag) != 48) goto handle_unusual;
        ::google::protobuf::uint64 val = ::google::protobuf::internal::ReadVarint(&ptr);
        msg->set_type(static_cast<::st::proxy::proto::record_type>(val));
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr);
        break;
      }
      default: {
      handle_unusual:
        if ((tag & 7) == 4 || tag == 0) {
          ctx->EndGroup(tag);
          return ptr;
        }
        auto res = UnknownFieldParse(tag, {_InternalParse, msg},
          ptr, end, msg->_internal_metadata_.mutable_unknown_fields(), ctx);
        ptr = res.first;
        GOOGLE_PROTOBUF_PARSER_ASSERT(ptr != nullptr);
        if (res.second) return ptr;
      }
    }  // switch
  }  // while
  return ptr;
len_delim_till_end:
  return ctx->StoreAndTailCall(ptr, end, {_InternalParse, msg},
                               {parser_till_end, object}, size);
}
#else  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER
bool quality_record::MergePartialFromCodedStream(
    ::google::protobuf::io::CodedInputStream* input) {
#define DO_(EXPRESSION) if (!PROTOBUF_PREDICT_TRUE(EXPRESSION)) goto failure
  ::google::protobuf::uint32 tag;
  ::google::protobuf::internal::LiteUnknownFieldSetter unknown_fields_setter(
      &_internal_metadata_);
  ::google::protobuf::io::StringOutputStream unknown_fields_output(
      unknown_fields_setter.buffer());
  ::google::protobuf::io::CodedOutputStream unknown_fields_stream(
      &unknown_fields_output, false);
  // @@protoc_insertion_point(parse_start:st.proxy.proto.quality_record)
  for (;;) {
    ::std::pair<::google::protobuf::uint32, bool> p = input->ReadTagWithCutoffNoLastTag(127u);
    tag = p.first;
    if (!p.second) goto handle_unusual;
    switch (::google::protobuf::internal::WireFormatLite::GetTagFieldNumber(tag)) {
      // repeated .st.proxy.proto.session_record records = 1;
      case 1: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (10 & 0xFF)) {
          DO_(::google::protobuf::internal::WireFormatLite::ReadMessage(
                input, add_records()));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint32 queue_size = 2;
      case 2: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (16 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &queue_size_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint32 first_package_cost = 3;
      case 3: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (24 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &first_package_cost_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint32 first_package_success = 4;
      case 4: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (32 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &first_package_success_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // uint32 first_package_failed = 5;
      case 5: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (40 & 0xFF)) {

          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   ::google::protobuf::uint32, ::google::protobuf::internal::WireFormatLite::TYPE_UINT32>(
                 input, &first_package_failed_)));
        } else {
          goto handle_unusual;
        }
        break;
      }

      // .st.proxy.proto.record_type type = 6;
      case 6: {
        if (static_cast< ::google::protobuf::uint8>(tag) == (48 & 0xFF)) {
          int value = 0;
          DO_((::google::protobuf::internal::WireFormatLite::ReadPrimitive<
                   int, ::google::protobuf::internal::WireFormatLite::TYPE_ENUM>(
                 input, &value)));
          set_type(static_cast< ::st::proxy::proto::record_type >(value));
        } else {
          goto handle_unusual;
        }
        break;
      }

      default: {
      handle_unusual:
        if (tag == 0) {
          goto success;
        }
        DO_(::google::protobuf::internal::WireFormatLite::SkipField(
            input, tag, &unknown_fields_stream));
        break;
      }
    }
  }
success:
  // @@protoc_insertion_point(parse_success:st.proxy.proto.quality_record)
  return true;
failure:
  // @@protoc_insertion_point(parse_failure:st.proxy.proto.quality_record)
  return false;
#undef DO_
}
#endif  // GOOGLE_PROTOBUF_ENABLE_EXPERIMENTAL_PARSER

void quality_record::SerializeWithCachedSizes(
    ::google::protobuf::io::CodedOutputStream* output) const {
  // @@protoc_insertion_point(serialize_start:st.proxy.proto.quality_record)
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  // repeated .st.proxy.proto.session_record records = 1;
  for (unsigned int i = 0,
      n = static_cast<unsigned int>(this->records_size()); i < n; i++) {
    ::google::protobuf::internal::WireFormatLite::WriteMessage(
      1,
      this->records(static_cast<int>(i)),
      output);
  }

  // uint32 queue_size = 2;
  if (this->queue_size() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(2, this->queue_size(), output);
  }

  // uint32 first_package_cost = 3;
  if (this->first_package_cost() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(3, this->first_package_cost(), output);
  }

  // uint32 first_package_success = 4;
  if (this->first_package_success() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(4, this->first_package_success(), output);
  }

  // uint32 first_package_failed = 5;
  if (this->first_package_failed() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteUInt32(5, this->first_package_failed(), output);
  }

  // .st.proxy.proto.record_type type = 6;
  if (this->type() != 0) {
    ::google::protobuf::internal::WireFormatLite::WriteEnum(
      6, this->type(), output);
  }

  output->WriteRaw(_internal_metadata_.unknown_fields().data(),
                   static_cast<int>(_internal_metadata_.unknown_fields().size()));
  // @@protoc_insertion_point(serialize_end:st.proxy.proto.quality_record)
}

size_t quality_record::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:st.proxy.proto.quality_record)
  size_t total_size = 0;

  total_size += _internal_metadata_.unknown_fields().size();

  ::google::protobuf::uint32 cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // repeated .st.proxy.proto.session_record records = 1;
  {
    unsigned int count = static_cast<unsigned int>(this->records_size());
    total_size += 1UL * count;
    for (unsigned int i = 0; i < count; i++) {
      total_size +=
        ::google::protobuf::internal::WireFormatLite::MessageSize(
          this->records(static_cast<int>(i)));
    }
  }

  // uint32 queue_size = 2;
  if (this->queue_size() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt32Size(
        this->queue_size());
  }

  // uint32 first_package_cost = 3;
  if (this->first_package_cost() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt32Size(
        this->first_package_cost());
  }

  // uint32 first_package_success = 4;
  if (this->first_package_success() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt32Size(
        this->first_package_success());
  }

  // uint32 first_package_failed = 5;
  if (this->first_package_failed() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::UInt32Size(
        this->first_package_failed());
  }

  // .st.proxy.proto.record_type type = 6;
  if (this->type() != 0) {
    total_size += 1 +
      ::google::protobuf::internal::WireFormatLite::EnumSize(this->type());
  }

  int cached_size = ::google::protobuf::internal::ToCachedSize(total_size);
  SetCachedSize(cached_size);
  return total_size;
}

void quality_record::CheckTypeAndMergeFrom(
    const ::google::protobuf::MessageLite& from) {
  MergeFrom(*::google::protobuf::down_cast<const quality_record*>(&from));
}

void quality_record::MergeFrom(const quality_record& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:st.proxy.proto.quality_record)
  GOOGLE_DCHECK_NE(&from, this);
  _internal_metadata_.MergeFrom(from._internal_metadata_);
  ::google::protobuf::uint32 cached_has_bits = 0;
  (void) cached_has_bits;

  records_.MergeFrom(from.records_);
  if (from.queue_size() != 0) {
    set_queue_size(from.queue_size());
  }
  if (from.first_package_cost() != 0) {
    set_first_package_cost(from.first_package_cost());
  }
  if (from.first_package_success() != 0) {
    set_first_package_success(from.first_package_success());
  }
  if (from.first_package_failed() != 0) {
    set_first_package_failed(from.first_package_failed());
  }
  if (from.type() != 0) {
    set_type(from.type());
  }
}

void quality_record::CopyFrom(const quality_record& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:st.proxy.proto.quality_record)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool quality_record::IsInitialized() const {
  return true;
}

void quality_record::Swap(quality_record* other) {
  if (other == this) return;
  InternalSwap(other);
}
void quality_record::InternalSwap(quality_record* other) {
  using std::swap;
  _internal_metadata_.Swap(&other->_internal_metadata_);
  CastToBase(&records_)->InternalSwap(CastToBase(&other->records_));
  swap(queue_size_, other->queue_size_);
  swap(first_package_cost_, other->first_package_cost_);
  swap(first_package_success_, other->first_package_success_);
  swap(first_package_failed_, other->first_package_failed_);
  swap(type_, other->type_);
}

::std::string quality_record::GetTypeName() const {
  return "st.proxy.proto.quality_record";
}


// @@protoc_insertion_point(namespace_scope)
}  // namespace proto
}  // namespace proxy
}  // namespace st
namespace google {
namespace protobuf {
template<> PROTOBUF_NOINLINE ::st::proxy::proto::session_record* Arena::CreateMaybeMessage< ::st::proxy::proto::session_record >(Arena* arena) {
  return Arena::CreateInternal< ::st::proxy::proto::session_record >(arena);
}
template<> PROTOBUF_NOINLINE ::st::proxy::proto::quality_record* Arena::CreateMaybeMessage< ::st::proxy::proto::quality_record >(Arena* arena) {
  return Arena::CreateInternal< ::st::proxy::proto::quality_record >(arena);
}
}  // namespace protobuf
}  // namespace google

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>
