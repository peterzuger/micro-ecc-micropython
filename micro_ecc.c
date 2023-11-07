/**
 * @file   micro-ecc-micropython/micro_ecc.c
 * @author Peter Züger
 * @date   23.06.2023
 * @brief  micro-ecc wrapper for micropython
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2023 Peter Züger
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "py/mpconfig.h"

#if defined(MODULE_MICRO_ECC_ENABLED) && MODULE_MICRO_ECC_ENABLED == 1

#include "py/obj.h"
#include "py/runtime.h"
#include "py/objarray.h"

#include <string.h>

#include "uECC.h"

static void micro_ecc_mp_obj_get_data(mp_obj_t data_p, const uint8_t** data, size_t* size){
    if(mp_obj_is_type(data_p, &mp_type_bytearray) || mp_obj_is_type(data_p, &mp_type_memoryview)){
        *data = (const uint8_t*)((mp_obj_array_t*)data_p)->items;
        *size = ((mp_obj_array_t*)data_p)->len;
    }else{
        // raises TypeError
        *data = (const uint8_t*)mp_obj_str_get_data(data_p, size);
    }
}


typedef struct _micro_ecc_Curve_obj_t{
    // base represents some basic information, like type
    mp_obj_base_t base;

    uECC_Curve curve;
    size_t curve_size;
    char curve_name[10];
}micro_ecc_Curve_obj_t;


mp_obj_t micro_ecc_Curve_make_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args);
STATIC void micro_ecc_Curve_print(const mp_print_t* print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t micro_ecc_Curve_curve_size(mp_obj_t self_in);
STATIC mp_obj_t micro_ecc_Curve_private_key_size(mp_obj_t self_in);
STATIC mp_obj_t micro_ecc_Curve_public_key_size(mp_obj_t self_in);
STATIC mp_obj_t micro_ecc_Curve_make_key(mp_obj_t self_in);
STATIC mp_obj_t micro_ecc_Curve_shared_secret(mp_obj_t self_in, mp_obj_t public_key_in, mp_obj_t private_key_in);
#if uECC_SUPPORT_COMPRESSED_POINT
STATIC mp_obj_t micro_ecc_Curve_compress(mp_obj_t self_in, mp_obj_t public_key_in);
STATIC mp_obj_t micro_ecc_Curve_decompress(mp_obj_t self_in, mp_obj_t compressed_in);
#endif /* uECC_SUPPORT_COMPRESSED_POINT */
STATIC mp_obj_t micro_ecc_Curve_valid_public_key(mp_obj_t public_key_in, mp_obj_t self_in);
STATIC mp_obj_t micro_ecc_Curve_compute_public_key(mp_obj_t self_in, mp_obj_t private_key_in);
STATIC mp_obj_t micro_ecc_Curve_sign(mp_obj_t self_in, mp_obj_t private_key_in, mp_obj_t message_hash_in);
STATIC mp_obj_t micro_ecc_Curve_verify(size_t n_args, const mp_obj_t* args);

STATIC MP_DEFINE_CONST_FUN_OBJ_1(micro_ecc_Curve_curve_size_fun_obj, micro_ecc_Curve_curve_size);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(micro_ecc_Curve_private_key_size_fun_obj, micro_ecc_Curve_private_key_size);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(micro_ecc_Curve_public_key_size_fun_obj, micro_ecc_Curve_public_key_size);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(micro_ecc_Curve_make_key_fun_obj, micro_ecc_Curve_make_key);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(micro_ecc_Curve_shared_secret_fun_obj, micro_ecc_Curve_shared_secret);
#if uECC_SUPPORT_COMPRESSED_POINT
STATIC MP_DEFINE_CONST_FUN_OBJ_2(micro_ecc_Curve_compress_fun_obj, micro_ecc_Curve_compress);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(micro_ecc_Curve_decompress_fun_obj, micro_ecc_Curve_decompress);
#endif /* uECC_SUPPORT_COMPRESSED_POINT */
STATIC MP_DEFINE_CONST_FUN_OBJ_2(micro_ecc_Curve_valid_public_key_fun_obj, micro_ecc_Curve_valid_public_key);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(micro_ecc_Curve_compute_public_key_fun_obj, micro_ecc_Curve_compute_public_key);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(micro_ecc_Curve_sign_fun_obj, micro_ecc_Curve_sign);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(micro_ecc_Curve_verify_fun_obj, 4, 4, micro_ecc_Curve_verify);

STATIC const mp_rom_map_elem_t micro_ecc_Curve_locals_dict_table[] = {
    // class methods
    { MP_ROM_QSTR(MP_QSTR_curve_size),         MP_ROM_PTR(&micro_ecc_Curve_curve_size_fun_obj)         },
    { MP_ROM_QSTR(MP_QSTR_private_key_size),   MP_ROM_PTR(&micro_ecc_Curve_private_key_size_fun_obj)   },
    { MP_ROM_QSTR(MP_QSTR_public_key_size),    MP_ROM_PTR(&micro_ecc_Curve_public_key_size_fun_obj)    },
    { MP_ROM_QSTR(MP_QSTR_make_key),           MP_ROM_PTR(&micro_ecc_Curve_make_key_fun_obj)           },
    { MP_ROM_QSTR(MP_QSTR_shared_secret),      MP_ROM_PTR(&micro_ecc_Curve_shared_secret_fun_obj)      },
    { MP_ROM_QSTR(MP_QSTR_valid_public_key),   MP_ROM_PTR(&micro_ecc_Curve_valid_public_key_fun_obj)   },
    { MP_ROM_QSTR(MP_QSTR_compute_public_key), MP_ROM_PTR(&micro_ecc_Curve_compute_public_key_fun_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign),               MP_ROM_PTR(&micro_ecc_Curve_sign_fun_obj)               },
    { MP_ROM_QSTR(MP_QSTR_verify),             MP_ROM_PTR(&micro_ecc_Curve_verify_fun_obj)             },
#if uECC_SUPPORT_COMPRESSED_POINT
    { MP_ROM_QSTR(MP_QSTR_decompress),         MP_ROM_PTR(&micro_ecc_Curve_decompress_fun_obj)         },
    { MP_ROM_QSTR(MP_QSTR_compress),           MP_ROM_PTR(&micro_ecc_Curve_compress_fun_obj)           },
#endif /* uECC_SUPPORT_COMPRESSED_POINT */
};
STATIC MP_DEFINE_CONST_DICT(micro_ecc_Curve_locals_dict, micro_ecc_Curve_locals_dict_table);


MP_DEFINE_CONST_OBJ_TYPE(
    micro_ecc_Curve_type,
    MP_QSTR_Curve,
    MP_TYPE_FLAG_NONE,
    print, micro_ecc_Curve_print,
    make_new, micro_ecc_Curve_make_new,
    locals_dict, &micro_ecc_Curve_locals_dict
    );

/**
 * Python: micro_ecc.Curve()
 */
mp_obj_t micro_ecc_Curve_make_new(const mp_obj_type_t* type,
                                  size_t n_args,
                                  size_t n_kw,
                                  const mp_obj_t* args){
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    // raises MemoryError
    micro_ecc_Curve_obj_t* self = mp_obj_malloc(micro_ecc_Curve_obj_t, type);

    size_t size;

    // raises TypeError
    const char* curve_name = mp_obj_str_get_data(args[0], &size);

    self->curve_size = 0;

    if(size == 9){
        strncpy(self->curve_name, curve_name, 9);
#if uECC_SUPPORTS_secp160r1
        if(strncmp(curve_name, "secp160r1", 9) == 0){
            self->curve = uECC_secp160r1();
            self->curve_size = 20;
        }
#endif
#if uECC_SUPPORTS_secp192r1
        if(strncmp(curve_name, "secp192r1", 9) == 0){
            self->curve = uECC_secp192r1();
            self->curve_size = 24;
        }
#endif
#if uECC_SUPPORTS_secp224r1
        if(strncmp(curve_name, "secp224r1", 9) == 0){
            self->curve = uECC_secp224r1();
            self->curve_size = 28;
        }
#endif
#if uECC_SUPPORTS_secp256r1
        if(strncmp(curve_name, "secp256r1", 9) == 0){
            self->curve = uECC_secp256r1();
            self->curve_size = 32;
        }
#endif
#if uECC_SUPPORTS_secp256k1
        if(strncmp(curve_name, "secp256k1", 9) == 0){
            self->curve = uECC_secp256k1();
            self->curve_size = 32;
        }
#endif
    }

    if(self->curve_size == 0){
        mp_raise_msg_varg(&mp_type_ValueError, MP_ERROR_TEXT("Unknown curve specified: %s"), curve_name);
    }

    return MP_OBJ_FROM_PTR(self);
}

/**
 * Python: print(micro_ecc.Curve())
 * @param obj
 */
STATIC void micro_ecc_Curve_print(const mp_print_t* print,
                                  mp_obj_t self_in, mp_print_kind_t kind){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "Curve(%s)", self->curve_name);
}

static const uint8_t* Curve_get_public_key(micro_ecc_Curve_obj_t* self, mp_obj_t public_key_in){
    size_t public_key_size;

    // raises TypeError
    const char* public_key = mp_obj_str_get_data(public_key_in, &public_key_size);

    if(public_key_size != (size_t)uECC_curve_public_key_size(self->curve)){
        mp_raise_ValueError(MP_ERROR_TEXT("Public Key has the wrong size"));
    }

    return (const uint8_t*)public_key;
}

static const uint8_t* Curve_get_private_key(micro_ecc_Curve_obj_t* self, mp_obj_t private_key_in){
    size_t private_key_size;

    // raises TypeError
    const char* private_key = mp_obj_str_get_data(private_key_in, &private_key_size);

    if(private_key_size != (size_t)uECC_curve_private_key_size(self->curve)){
        mp_raise_ValueError(MP_ERROR_TEXT("Private Key has the wrong size"));
    }

    return (const uint8_t*)private_key;
}

/**
 * Python: micro_ecc.Curve.curve_size(self)
 * @param self
 */
STATIC mp_obj_t micro_ecc_Curve_curve_size(mp_obj_t self_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_int(self->curve_size);
}

/**
 * Python: micro_ecc.Curve.private_key_size(self)
 * @param self
 */
STATIC mp_obj_t micro_ecc_Curve_private_key_size(mp_obj_t self_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_int(uECC_curve_private_key_size(self->curve));
}

/**
 * Python: micro_ecc.Curve.public_key_size(self)
 * @param self
 */
STATIC mp_obj_t micro_ecc_Curve_public_key_size(mp_obj_t self_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_int(uECC_curve_public_key_size(self->curve));
}

/**
 * Python: micro_ecc.Curve.make_key(self)
 * @param self
 */
STATIC mp_obj_t micro_ecc_Curve_make_key(mp_obj_t self_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    vstr_t vstr_public;
    vstr_init_len(&vstr_public, uECC_curve_public_key_size(self->curve));

    vstr_t vstr_private;
    vstr_init_len(&vstr_private, uECC_curve_private_key_size(self->curve));

    int ret = uECC_make_key((uint8_t*)vstr_public.buf, (uint8_t*)vstr_private.buf, self->curve);

    if(ret != 1){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("uECC_make_key() failed"));
    }

    mp_obj_t tuple[2] = {
        mp_obj_new_bytes_from_vstr(&vstr_public),
        mp_obj_new_bytes_from_vstr(&vstr_private),
    };

    return mp_obj_new_tuple(2, tuple);
}

/**
 * Python: micro_ecc.Curve.shared_secret(self, public_key, private_key)
 * @param self
 * @param public_key
 * @param private_key
 */
STATIC mp_obj_t micro_ecc_Curve_shared_secret(mp_obj_t self_in, mp_obj_t public_key_in, mp_obj_t private_key_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises TypeError, ValueError
    const uint8_t* public_key = Curve_get_public_key(self, public_key_in);
    const uint8_t* private_key = Curve_get_private_key(self, private_key_in);

    vstr_t vstr;
    vstr_init_len(&vstr, self->curve_size);

    int ret = uECC_shared_secret(public_key,
                                 private_key,
                                 (uint8_t*)vstr.buf,
                                 self->curve);

    if(ret != 1){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("uECC_shared_secret() failed"));
    }

    return mp_obj_new_bytes_from_vstr(&vstr);
}

#if uECC_SUPPORT_COMPRESSED_POINT
/**
 * Python: micro_ecc.Curve.compress(self, public_key)
 * @param self
 * @param public_key
 */
STATIC mp_obj_t micro_ecc_Curve_compress(mp_obj_t self_in, mp_obj_t public_key_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises TypeError, ValueError
    const uint8_t* public_key = Curve_get_public_key(self, public_key_in);

    vstr_t vstr;
    vstr_init_len(&vstr, self->curve_size + 1);

    uECC_compress(public_key, (uint8_t*)vstr.buf, self->curve);

    return mp_obj_new_bytes_from_vstr(&vstr);
}


/**
 * Python: micro_ecc.Curve.decompress(self, compressed)
 * @param self
 * @param compressed
 */
STATIC mp_obj_t micro_ecc_Curve_decompress(mp_obj_t self_in, mp_obj_t compressed_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    size_t compressed_size;
    const uint8_t* compressed;

    // raises TypeError
    micro_ecc_mp_obj_get_data(compressed_in, &compressed, &compressed_size);

    if(compressed_size != (self->curve_size + 1)){
        mp_raise_ValueError(MP_ERROR_TEXT("Compressed Public Key has the wrong size"));
    }

    vstr_t vstr;
    vstr_init_len(&vstr, uECC_curve_public_key_size(self->curve));

    uECC_decompress(compressed, (uint8_t*)vstr.buf, self->curve);

    return mp_obj_new_bytes_from_vstr(&vstr);
}
#endif /* uECC_SUPPORT_COMPRESSED_POINT */

/**
 * Python: micro_ecc.Curve.valid_public_key(self, public_key)
 * @param self
 * @param public_key
 */
STATIC mp_obj_t micro_ecc_Curve_valid_public_key(mp_obj_t self_in, mp_obj_t public_key_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises TypeError, ValueError
    const uint8_t* public_key = Curve_get_public_key(self, public_key_in);

    return mp_obj_new_bool(uECC_valid_public_key(public_key, self->curve));
}

/**
 * Python: micro_ecc.Curve.compute_public_key(self, private_key)
 * @param self
 * @param private_key
 */
STATIC mp_obj_t micro_ecc_Curve_compute_public_key(mp_obj_t self_in, mp_obj_t private_key_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises TypeError, ValueError
    const uint8_t* private_key = Curve_get_private_key(self, private_key_in);

    vstr_t vstr;
    vstr_init_len(&vstr, uECC_curve_public_key_size(self->curve));

    int ret = uECC_compute_public_key(private_key,
                                      (uint8_t*)vstr.buf,
                                      self->curve);

    if(ret != 1){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("uECC_compute_public_key() failed"));
    }

    return mp_obj_new_bytes_from_vstr(&vstr);
}

/**
 * Python: micro_ecc.Curve.sign(self, private_key, message_hash)
 * @param self
 * @param private_key
 * @param message_hash
 */
STATIC mp_obj_t micro_ecc_Curve_sign(mp_obj_t self_in, mp_obj_t private_key_in, mp_obj_t message_hash_in){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises TypeError, ValueError
    const uint8_t* private_key = Curve_get_private_key(self, private_key_in);

    size_t hash_size;
    const uint8_t* message_hash;

    // raises TypeError
    micro_ecc_mp_obj_get_data(message_hash_in, &message_hash, &hash_size);

    vstr_t vstr;
    vstr_init_len(&vstr, self->curve_size * 2);

    int ret = uECC_sign(private_key,
                        message_hash,
                        hash_size,
                        (uint8_t*)vstr.buf,
                        self->curve);

    if(ret != 1){
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("uECC_compute_public_key() failed"));
    }

    return mp_obj_new_bytes_from_vstr(&vstr);
}

/**
 * Python: micro_ecc.Curve.verify(self, public_key, message_hash, signature)
 * @param args[0] self
 * @param args[1] public_key
 * @param args[2] message_hash
 * @param args[3] signature
 */
STATIC mp_obj_t micro_ecc_Curve_verify(size_t n_args, const mp_obj_t* args){
    micro_ecc_Curve_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    // raises TypeError, ValueError
    const uint8_t* public_key = Curve_get_public_key(self, args[1]);

    size_t hash_size;
    const uint8_t* message_hash;

    // raises TypeError
    micro_ecc_mp_obj_get_data(args[2], &message_hash, &hash_size);

    size_t signature_size;
    const uint8_t* signature;

    // raises TypeError
    micro_ecc_mp_obj_get_data(args[3], &signature, &signature_size);

    if(signature_size != (self->curve_size * 2)){
        mp_raise_ValueError(MP_ERROR_TEXT("Signature has the wrong size"));
    }

    int ret = uECC_verify(public_key,
                          message_hash,
                          hash_size,
                          signature,
                          self->curve);

    return mp_obj_new_bool(ret);
}

/**
 * Python: micro_ecc.curves()
 */
STATIC mp_obj_t micro_ecc_curves(void){
    mp_obj_t tuple[] = {
#if uECC_SUPPORTS_secp160r1
        MP_ROM_QSTR(MP_QSTR_secp160r1),
#endif
#if uECC_SUPPORTS_secp192r1
        MP_ROM_QSTR(MP_QSTR_secp192r1),
#endif
#if uECC_SUPPORTS_secp224r1
        MP_ROM_QSTR(MP_QSTR_secp224r1),
#endif
#if uECC_SUPPORTS_secp256r1
        MP_ROM_QSTR(MP_QSTR_secp256r1),
#endif
#if uECC_SUPPORTS_secp256k1
        MP_ROM_QSTR(MP_QSTR_secp256k1),
#endif
    };

    return mp_obj_new_tuple(MP_ARRAY_SIZE(tuple), tuple);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(micro_ecc_curves_fun_obj, micro_ecc_curves);


STATIC const mp_rom_map_elem_t micro_ecc_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_uECC)             },
    { MP_ROM_QSTR(MP_QSTR_curves),   MP_ROM_PTR(&micro_ecc_curves_fun_obj) },

    { MP_ROM_QSTR(MP_QSTR_Curve),    MP_ROM_PTR(&micro_ecc_Curve_type)     },
};

STATIC MP_DEFINE_CONST_DICT(
    mp_module_micro_ecc_globals,
    micro_ecc_globals_table
    );

const mp_obj_module_t mp_module_micro_ecc = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_micro_ecc_globals,
};

MP_REGISTER_MODULE(MP_QSTR_uECC, mp_module_micro_ecc);

#endif /* defined(MODULE_MICRO_ECC_ENABLED) && MODULE_MICRO_ECC_ENABLED == 1 */
