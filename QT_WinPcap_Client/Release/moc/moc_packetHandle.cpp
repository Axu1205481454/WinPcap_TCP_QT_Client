/****************************************************************************
** Meta object code from reading C++ file 'packetHandle.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.12.2)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "../../packetHandle.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'packetHandle.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.12.2. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_PacketHandle_t {
    QByteArrayData data[10];
    char stringdata0[138];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_PacketHandle_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_PacketHandle_t qt_meta_stringdata_PacketHandle = {
    {
QT_MOC_LITERAL(0, 0, 12), // "PacketHandle"
QT_MOC_LITERAL(1, 13, 12), // "packetSignal"
QT_MOC_LITERAL(2, 26, 0), // ""
QT_MOC_LITERAL(3, 27, 4), // "info"
QT_MOC_LITERAL(4, 32, 18), // "packetStaticSignal"
QT_MOC_LITERAL(5, 51, 16), // "connStatusSignal"
QT_MOC_LITERAL(6, 68, 8), // "connFlag"
QT_MOC_LITERAL(7, 77, 22), // "connStatusStaticSignal"
QT_MOC_LITERAL(8, 100, 16), // "packetStaticSlot"
QT_MOC_LITERAL(9, 117, 20) // "connStatusStaticSlot"

    },
    "PacketHandle\0packetSignal\0\0info\0"
    "packetStaticSignal\0connStatusSignal\0"
    "connFlag\0connStatusStaticSignal\0"
    "packetStaticSlot\0connStatusStaticSlot"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_PacketHandle[] = {

 // content:
       8,       // revision
       0,       // classname
       0,    0, // classinfo
       6,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       4,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   44,    2, 0x06 /* Public */,
       4,    1,   47,    2, 0x06 /* Public */,
       5,    1,   50,    2, 0x06 /* Public */,
       7,    1,   53,    2, 0x06 /* Public */,

 // slots: name, argc, parameters, tag, flags
       8,    1,   56,    2, 0x08 /* Private */,
       9,    1,   59,    2, 0x08 /* Private */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::Int,    6,
    QMetaType::Void, QMetaType::Int,    6,

 // slots: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::Int,    6,

       0        // eod
};

void PacketHandle::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        auto *_t = static_cast<PacketHandle *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->packetSignal((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 1: _t->packetStaticSignal((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 2: _t->connStatusSignal((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 3: _t->connStatusStaticSignal((*reinterpret_cast< int(*)>(_a[1]))); break;
        case 4: _t->packetStaticSlot((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 5: _t->connStatusStaticSlot((*reinterpret_cast< int(*)>(_a[1]))); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            using _t = void (PacketHandle::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketHandle::packetSignal)) {
                *result = 0;
                return;
            }
        }
        {
            using _t = void (PacketHandle::*)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketHandle::packetStaticSignal)) {
                *result = 1;
                return;
            }
        }
        {
            using _t = void (PacketHandle::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketHandle::connStatusSignal)) {
                *result = 2;
                return;
            }
        }
        {
            using _t = void (PacketHandle::*)(int );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&PacketHandle::connStatusStaticSignal)) {
                *result = 3;
                return;
            }
        }
    }
}

QT_INIT_METAOBJECT const QMetaObject PacketHandle::staticMetaObject = { {
    &QThread::staticMetaObject,
    qt_meta_stringdata_PacketHandle.data,
    qt_meta_data_PacketHandle,
    qt_static_metacall,
    nullptr,
    nullptr
} };


const QMetaObject *PacketHandle::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *PacketHandle::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_PacketHandle.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int PacketHandle::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 6)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 6;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 6)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 6;
    }
    return _id;
}

// SIGNAL 0
void PacketHandle::packetSignal(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void PacketHandle::packetStaticSignal(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void PacketHandle::connStatusSignal(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 2, _a);
}

// SIGNAL 3
void PacketHandle::connStatusStaticSignal(int _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
