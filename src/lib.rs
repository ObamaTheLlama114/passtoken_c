use std::{
    ffi::{c_char, c_int, c_ulong, CStr, c_void},
    mem,
};

fn get_error_code(err: core::AuthError) -> i8 {
    match err {
        core::AuthError::UserAlreadyExists => -1,
        core::AuthError::UserDoesNotExist => -2,
        core::AuthError::IncorrectUsernameOrPassword => -3,
        core::AuthError::InvalidToken => -4,
        core::AuthError::TokenDoesNotExist => -5,
        core::AuthError::UnableToAquireTokenListLock => -6,
        core::AuthError::PostgresError(_) => -7,
        core::AuthError::RedisError(_) => -8,
    }
}

#[repr(C)]
pub struct Auth {}

#[repr(C)]
pub enum StatusCode {
    Ok,
    Err,
}

#[repr(C)]
pub struct AuthResult {
    status_code: StatusCode,
    result: AuthUnion,
}

#[repr(C)]
pub union AuthUnion {
    ok: *mut core::Auth,
    err: c_int,
}

#[repr(C)]
pub struct CharResult {
    status_code: StatusCode,
    result: CharUnion,
}

#[repr(C)]
pub union CharUnion {
    ok: *mut c_char,
    err: i8,
}

#[no_mangle]
pub extern "C" fn set_token_expire_time(auth: *mut core::Auth, time: *mut c_ulong) {
    unsafe {
        if time.is_null() {
            (*auth).token_expire_time = None;
        } else {
            (*auth).token_expire_time = Some(*time as usize);
        }
    }
}

#[no_mangle]
pub extern "C" fn init_auth(postgres_url: *mut c_char, redis_url: *mut c_char) -> AuthResult {
    fn error(code: i8) -> AuthResult {
        AuthResult {
            status_code: StatusCode::Err,
            result: AuthUnion { err: code.into() },
        }
    }
    let postgres_url = match unsafe { CStr::from_ptr(postgres_url) }.to_str() {
        Ok(s) => s,
        Err(_) => return error(-9),
    };
    let redis_url = match unsafe { CStr::from_ptr(redis_url) }.to_str() {
        Ok(s) => s,
        Err(_) => return error(-9),
    };
    let auth = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { core::init_auth(postgres_url.to_string(), redis_url.to_string()).await });
    let auth = match auth {
        Ok(a) => a,
        Err(err) => return error(get_error_code(err)),
    };
    AuthResult {
        status_code: StatusCode::Ok,
        result: AuthUnion {
            ok: Box::into_raw(Box::new(auth)),
        },
    }
}

#[no_mangle]
pub extern "C" fn deinit_auth(auth: *mut core::Auth) {
    unsafe {
        libc::free(auth as *mut c_void);
    }
}

#[no_mangle]
pub extern "C" fn create_user(
    auth: *mut core::Auth,
    email: *mut c_char,
    password: *mut c_char,
) -> c_int {
    let email = match unsafe { CStr::from_ptr(email) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    let password = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };

    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            core::create_user(
                unsafe { &mut *auth },
                email.to_string(),
                password.to_string(),
            )
            .await
        }) {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn login(
    auth: *mut core::Auth,
    email: *mut c_char,
    password: *mut c_char,
) -> CharResult {
    fn error(code: i8) -> CharResult {
        CharResult {
            status_code: StatusCode::Err,
            result: CharUnion { err: code.into() },
        }
    }
    let email = match unsafe { CStr::from_ptr(email) }.to_str() {
        Ok(s) => s,
        Err(_) => return error(-9),
    };
    let password = match unsafe { CStr::from_ptr(password) }.to_str() {
        Ok(s) => s,
        Err(_) => return error(-9),
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            core::login(
                unsafe { &mut *auth },
                email.to_string(),
                password.to_string(),
            )
            .await
        }) {
        Ok(token) => CharResult {
            status_code: StatusCode::Ok,
            result: CharUnion {
                ok: {
                    let mut chars: Vec<c_char> =
                        token.chars().map(|x| x as c_char).collect::<Vec<c_char>>();
                    chars.push('\0' as c_char);
                    unsafe {
                        let ptr = libc::malloc(mem::size_of::<i8>() * chars.len()) as *mut c_char;
                        for i in 0..chars.len() {
                            *ptr.offset(i.try_into().unwrap()) = chars[i];
                        }
                        ptr
                    }
                },
            },
        },
        Err(err) => error(get_error_code(err)),
    }
}

#[no_mangle]
pub extern "C" fn logout(auth: *mut core::Auth, token: *mut c_char) -> c_int {
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    match core::logout(unsafe { &mut *auth }, token.to_string()) {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn update_user(
    auth: *mut core::Auth,
    token: *mut c_char,
    email: *mut c_char,
    password: *mut c_char,
    logout: bool,
) -> c_int {
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    let email = if email.is_null() {
        Some(
            match unsafe { CStr::from_ptr(email) }.to_str() {
                Ok(s) => s,
                Err(_) => return -9,
            }
            .to_string(),
        )
    } else {
        None
    };
    let password = if password.is_null() {
        Some(
            match unsafe { CStr::from_ptr(password) }.to_str() {
                Ok(s) => s,
                Err(_) => return -9,
            }
            .to_string(),
        )
    } else {
        None
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            core::update_user(
                unsafe { &mut *auth },
                token.to_string(),
                email,
                password,
                logout,
            )
            .await
        }) {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn admin_update_user(
    auth: *mut core::Auth,
    token: *mut c_char,
    email: *mut c_char,
    password: *mut c_char,
    logout: bool,
) -> c_int {
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    let email = if email.is_null() {
        Some(
            match unsafe { CStr::from_ptr(email) }.to_str() {
                Ok(s) => s,
                Err(_) => return -9,
            }
            .to_string(),
        )
    } else {
        None
    };
    let password = if password.is_null() {
        Some(
            match unsafe { CStr::from_ptr(password) }.to_str() {
                Ok(s) => s,
                Err(_) => return -9,
            }
            .to_string(),
        )
    } else {
        None
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            core::admin_update_user(
                unsafe { &mut *auth },
                token.to_string(),
                email,
                password,
                logout,
            )
            .await
        }) {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn delete_user(auth: *mut core::Auth, token: *mut c_char) -> c_int {
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { core::delete_user(unsafe { &mut *auth }, token.to_string()).await })
    {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn admin_delete_user(auth: *mut core::Auth, filter: *mut c_char) -> c_int {
    let filter = match unsafe { CStr::from_ptr(filter) }.to_str() {
        Ok(s) => s,
        Err(_) => return -9,
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            core::admin_delete_user(unsafe { &mut *auth }, filter.to_string()).await
        }) {
        Ok(_) => 0,
        Err(err) => get_error_code(err).into(),
    }
}

#[no_mangle]
pub extern "C" fn verify_token(auth: *mut core::Auth, token: *mut c_char) -> CharResult {
    fn error(code: i8) -> CharResult {
        CharResult {
            status_code: StatusCode::Err,
            result: CharUnion { err: code.into() },
        }
    }
    let token = match unsafe { CStr::from_ptr(token) }.to_str() {
        Ok(s) => s,
        Err(_) => return error(-9),
    };
    match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async { core::verify_token(unsafe { &mut *auth }, token.to_string()).await })
    {
        Ok(result) => {
            if result != "" {
                CharResult {
                    status_code: StatusCode::Ok,
                    result: CharUnion {
                        ok: {
                            let mut chars: Vec<c_char> =
                                result.chars().map(|x| x as c_char).collect::<Vec<c_char>>();
                            chars.push('\0' as c_char);
                            unsafe {
                                let ptr =
                                    libc::malloc(mem::size_of::<i8>() * chars.len()) as *mut c_char;
                                for i in 0..chars.len() {
                                    *ptr.offset(i.try_into().unwrap()) = chars[i];
                                }
                                ptr
                            }
                        },
                    },
                }
            } else {
                error(1)
            }
        }
        Err(err) => error(get_error_code(err)),
    }
}
