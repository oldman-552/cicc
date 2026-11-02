import type {Lang} from './types';
export const integrityStrings:Record<Lang,{match:string;mismatch:string;unknown:string;warning:string;digest:string}>={
 en:{match:'Stored checksum matches',mismatch:'Stored checksum does not match',unknown:'No checksum recorded',warning:'Stored alongside the snapshot; not tamper-proof or proof of authenticity.',digest:'SHA-256'},
 ar:{match:'تطابق بصمة التحقق المخزنة',mismatch:'لا تطابق بصمة التحقق المخزنة',unknown:'لم تُسجّل بصمة تحقق',warning:'تُخزّن البصمة مع اللقطة؛ ليست مقاومة للتلاعب ولا تثبت الأصالة.',digest:'SHA-256'},
 fa:{match:'هش ذخیره‌شده مطابقت دارد',mismatch:'هش ذخیره‌شده مطابقت ندارد',unknown:'هشی ثبت نشده است',warning:'هش کنار تصویر ذخیره می‌شود و ضد دستکاری یا اثبات اصالت نیست.',digest:'SHA-256'}
};
