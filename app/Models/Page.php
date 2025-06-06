<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Page extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'code',
        'page_category_id',
        'active',
        'created_by',
    'updated_by',
    ];

    /**
     * Define the relationship with the PageCategory model.
     */
    public function category()
    {
        return $this->belongsTo(PageCategory::class, 'page_category_id');
    }

    /**
     * Define the relationship with the UserRoleDetail model.
     */
    public function userRoleDetails()
    {
        return $this->hasMany(UserRoleDetail::class, 'page_id');
    }
    public function pageCategory()
    {
        return $this->belongsTo(PageCategory::class, 'page_category_id');
    }

}
